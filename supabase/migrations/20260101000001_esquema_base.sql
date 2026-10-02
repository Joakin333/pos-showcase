-- ============================================================================
-- 001 · Esquema base
-- ============================================================================
-- Tablas principales y funciones de credenciales y respaldo.
--
-- Modelo de datos:
--   * app_data: catálogo, clientes, lotes, turnos, usuarios, etc. Cada clave
--     guarda un arreglo JSON completo. La app tiene una copia en el
--     dispositivo para poder vender sin internet (ver README).
--   * ventas_registro / movimientos_registro: historial, una fila por venta o
--     movimiento. Solo se agregan filas; nunca se editan ni se borran.
--   * credenciales: claves, respuestas secretas y el código maestro, siempre
--     hasheados con PBKDF2. Sin políticas RLS: solo se accede por funciones.
--
-- Las migraciones siguientes ajustan permisos; la 009 deja el modelo de
-- seguridad final (sesiones de Supabase Auth y RLS por rol).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- Extensiones
--   pgcrypto vive en el esquema "extensions" (así funciona Supabase); las
--   funciones de abajo fijan search_path = public, extensions por esa razón.
--   pg_cron puede requerir activarse desde el panel (Database → Extensions).
-- ---------------------------------------------------------------------------
create extension if not exists pgcrypto with schema extensions;
create extension if not exists pg_cron with schema pg_catalog;

-- ---------------------------------------------------------------------------
-- Tablas
-- ---------------------------------------------------------------------------
-- Catálogo, clientes, lotes, turnos, usuarios, etc.: un arreglo JSON por clave.
create table if not exists public.app_data (
  key text not null primary key,
  value jsonb,
  updated_at timestamp with time zone default timezone('utc'::text, now())
);

-- Historial: una fila por venta / movimiento (solo se agregan filas).
create table if not exists public.ventas_registro (
  id text not null primary key,
  data jsonb not null,
  creado_en timestamp with time zone default now()
);

create table if not exists public.movimientos_registro (
  id text not null primary key,
  data jsonb not null,
  creado_en timestamp with time zone default now()
);

-- Credenciales vigentes (clave, respuesta secreta y código maestro '__maestro__'),
-- guardadas como bundle jsonb {algo:'pbkdf2', sal, iter, valor}.
create table if not exists public.credenciales (
  usuario_id text not null primary key,
  clave jsonb,
  respuesta jsonb,
  actualizado_en timestamp with time zone not null default now()
);

create table if not exists public.intentos_credencial (
  usuario_id text not null primary key,
  intentos integer not null default 0,
  bloqueado_hasta timestamp with time zone
);

-- Respaldos diarios de app_data (14 días).
create table if not exists public.respaldos_app_data (
  id bigint generated always as identity primary key,
  creado_en timestamp with time zone not null default now(),
  contenido jsonb not null
);

-- Tablas de un sistema de login anterior. La app ya no las usa; se conservan
-- selladas (RLS sin políticas) por compatibilidad con bases existentes.
create table if not exists public.credenciales_usuario (
  usuario_id text not null primary key,
  algo text not null,
  valor text not null,
  sal text,
  iter integer,
  resp_algo text,
  resp_valor text,
  resp_sal text,
  resp_iter integer,
  intentos_fallidos integer not null default 0,
  bloqueado_hasta timestamp with time zone,
  actualizado_en timestamp with time zone not null default now()
);

create table if not exists public.intentos_login (
  id bigserial primary key,
  usuario_id text not null,
  resultado text not null,
  creado_en timestamp with time zone not null default now()
);

-- Las tablas con datos sensibles quedan selladas (RLS sin políticas):
-- solo se acceden a través de funciones security definer.
alter table public.credenciales enable row level security;
alter table public.intentos_credencial enable row level security;
alter table public.respaldos_app_data enable row level security;
alter table public.credenciales_usuario enable row level security;
alter table public.intentos_login enable row level security;

-- ---------------------------------------------------------------------------
-- Funciones de credenciales (login server-side, PBKDF2 con bloqueo de intentos)
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.pbkdf2_hmac_sha256(p_password text, p_salt_hex text, p_iterations integer)
 RETURNS bytea
 LANGUAGE plpgsql
 SET search_path TO 'public', 'extensions'
AS $function$
declare
  salt bytea := decode(p_salt_hex, 'hex');
  bloque bytea := '\x00000001'::bytea;
  u bytea;
  t bytea;
  i int;
  j int;
begin
  u := hmac(salt || bloque, convert_to(p_password, 'UTF8'), 'sha256');
  t := u;
  for i in 2..p_iterations loop
    u := hmac(u, convert_to(p_password, 'UTF8'), 'sha256');
    for j in 0..31 loop
      t := set_byte(t, j, get_byte(u, j) # get_byte(t, j));
    end loop;
  end loop;
  return t;
end;
$function$
;

CREATE OR REPLACE FUNCTION public._verificar_bundle(p_bundle jsonb, p_texto text)
 RETURNS boolean
 LANGUAGE plpgsql
 SET search_path TO 'public', 'extensions'
AS $function$
declare
  algo text;
  valor text;
begin
  if p_bundle is null then return false; end if;
  if jsonb_typeof(p_bundle) = 'string' then
    return (p_bundle #>> '{}') = p_texto;
  end if;
  algo := p_bundle->>'algo';
  if algo = 'pbkdf2' then
    valor := encode(
      public.pbkdf2_hmac_sha256(p_texto, p_bundle->>'sal', (p_bundle->>'iter')::int),
      'hex'
    );
    return valor = (p_bundle->>'valor');
  elsif algo = 'plano' then
    return (p_bundle->>'valor') = p_texto;
  elsif algo = 'sha256' then
    return encode(digest('manifiesto::' || p_texto, 'sha256'), 'hex') = (p_bundle->>'valor');
  end if;
  return false;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.verificar_credencial(p_usuario_id text, p_tipo text, p_valor text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public', 'extensions'
AS $function$
declare
  fila record;
  cred record;
  bundle jsonb;
  ok boolean;
  nuevos_intentos int;
  nuevo_bundle jsonb;
  nueva_sal text;
begin
  if p_tipo not in ('clave','respuesta') then
    return jsonb_build_object('ok', false, 'error', 'tipo inválido');
  end if;

  select * into fila from public.intentos_credencial where usuario_id = p_usuario_id;
  if fila.bloqueado_hasta is not null and fila.bloqueado_hasta > now() then
    return jsonb_build_object('ok', false, 'bloqueado', true,
      'segundos', ceil(extract(epoch from fila.bloqueado_hasta - now()))::int);
  end if;

  select * into cred from public.credenciales where usuario_id = p_usuario_id;
  bundle := case when p_tipo='clave' then cred.clave else cred.respuesta end;
  ok := public._verificar_bundle(bundle, p_valor);

  if ok then
    delete from public.intentos_credencial where usuario_id = p_usuario_id;
    if jsonb_typeof(bundle) = 'string' or (bundle->>'algo') is distinct from 'pbkdf2' then
      nueva_sal := encode(gen_random_bytes(16), 'hex');
      nuevo_bundle := jsonb_build_object(
        'algo', 'pbkdf2',
        'sal', nueva_sal,
        'iter', 100000,
        'valor', encode(public.pbkdf2_hmac_sha256(p_valor, nueva_sal, 100000), 'hex')
      );
      insert into public.credenciales(usuario_id, clave, respuesta)
        values (
          p_usuario_id,
          case when p_tipo='clave' then nuevo_bundle end,
          case when p_tipo='respuesta' then nuevo_bundle end
        )
      on conflict (usuario_id) do update
        set clave = case when p_tipo='clave' then nuevo_bundle else public.credenciales.clave end,
            respuesta = case when p_tipo='respuesta' then nuevo_bundle else public.credenciales.respuesta end,
            actualizado_en = now();
    end if;
    return jsonb_build_object('ok', true);
  end if;

  nuevos_intentos := coalesce(fila.intentos, 0) + 1;
  if nuevos_intentos >= 5 then
    insert into public.intentos_credencial(usuario_id, intentos, bloqueado_hasta)
      values (p_usuario_id, 0, now() + interval '60 seconds')
      on conflict (usuario_id) do update
        set intentos = 0, bloqueado_hasta = now() + interval '60 seconds';
    return jsonb_build_object('ok', false, 'bloqueado', true, 'segundos', 60);
  else
    insert into public.intentos_credencial(usuario_id, intentos, bloqueado_hasta)
      values (p_usuario_id, nuevos_intentos, null)
      on conflict (usuario_id) do update
        set intentos = nuevos_intentos, bloqueado_hasta = null;
    return jsonb_build_object('ok', false, 'intentosRestantes', 5 - nuevos_intentos);
  end if;
end;
$function$
;

CREATE OR REPLACE FUNCTION public.guardar_credencial(p_usuario_id text, p_tipo text, p_valor_nuevo jsonb)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  if p_tipo not in ('clave','respuesta') then
    return jsonb_build_object('ok', false, 'error', 'tipo inválido');
  end if;
  insert into public.credenciales(usuario_id, clave, respuesta)
    values (
      p_usuario_id,
      case when p_tipo='clave' then p_valor_nuevo end,
      case when p_tipo='respuesta' then p_valor_nuevo end
    )
  on conflict (usuario_id) do update
    set clave = case when p_tipo='clave' then p_valor_nuevo else public.credenciales.clave end,
        respuesta = case when p_tipo='respuesta' then p_valor_nuevo else public.credenciales.respuesta end,
        actualizado_en = now();
  delete from public.intentos_credencial where usuario_id = p_usuario_id;
  return jsonb_build_object('ok', true);
end;
$function$
;

CREATE OR REPLACE FUNCTION public.eliminar_credencial(p_usuario_id text)
 RETURNS jsonb
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  delete from public.credenciales where usuario_id = p_usuario_id;
  delete from public.intentos_credencial where usuario_id = p_usuario_id;
  return jsonb_build_object('ok', true);
end;
$function$
;

-- Permisos iniciales. La migración 009 los restringe: guardar y eliminar
-- credenciales pasan a exigir sesión y a validar quién llama.
grant execute on function public.verificar_credencial(text, text, text) to anon, authenticated;
grant execute on function public.guardar_credencial(text, text, jsonb) to anon, authenticated;
grant execute on function public.eliminar_credencial(text) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- Respaldo diario de app_data (14 días). No cubre ventas_registro ni
-- movimientos_registro. La migración 006 cierra su acceso desde la API.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION public.fn_respaldo_diario()
 RETURNS void
 LANGUAGE plpgsql
 SECURITY DEFINER
 SET search_path TO 'public'
AS $function$
begin
  insert into respaldos_app_data (contenido)
  select jsonb_object_agg(key, value) from app_data;

  -- se guardan 14 días; más que eso no aporta mucho y ocupa espacio de más.
  delete from respaldos_app_data where creado_en < now() - interval '14 days';
end;
$function$
;

-- Cron: todos los días a las 07:00 UTC
do $$
begin
  if not exists (select 1 from cron.job where jobname = 'respaldo_diario_app_data') then
    perform cron.schedule('respaldo_diario_app_data', '0 7 * * *', $cron$ select fn_respaldo_diario(); $cron$);
  end if;
end $$;
