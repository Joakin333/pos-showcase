-- ============================================================================
-- 011 · Endurecimiento del login y de la recuperación de clave
-- ============================================================================
-- Dos riesgos que había que cerrar antes de operar con un cliente real:
--
--   1) Fuerza bruta contra el login. El bloqueo era de 60 s cada 5 intentos:
--      una clave de 4 dígitos (10.000 combinaciones) caía en unas 17 horas.
--      Ahora el bloqueo es PROGRESIVO (1 min, 5, 15 y 30 min), los intentos de
--      una misma cuenta se procesan de a uno (no se pueden probar claves en
--      paralelo) y la Edge Function limita además los intentos por IP.
--      Cada cuenta puede probarse, como mucho, ~10 veces por hora una vez
--      alcanzado el bloqueo máximo.
--
--   2) Envío masivo de códigos de recuperación. Ahora cada código se envía UNA
--      sola vez (la Edge Function lo "reclama" de forma atómica) y pedir
--      códigos nuevos tiene un límite por cuenta además del límite por IP.
--
-- Y una corrección: la IP del llamador se tomaba del primer valor de
-- X-Forwarded-For, que el cliente puede falsificar. Ahora se prefiere el
-- encabezado que fija la infraestructura (cf-connecting-ip).
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1) Bloqueo progresivo
-- ---------------------------------------------------------------------------
alter table public.intentos_credencial
  add column if not exists bloqueos int not null default 0,
  add column if not exists ultimo_fallo timestamptz;

-- now() es la hora de INICIO de la transacción: una petición lenta acortaría el bloqueo
-- justo por lo que tarda. Se usa el reloj real (clock_timestamp).
create or replace function public.verificar_credencial(p_usuario_id text, p_tipo text, p_valor text)
returns jsonb
language plpgsql
security definer
set search_path to 'public', 'extensions'
as $function$
declare
  fila record;
  cred record;
  bundle jsonb;
  ok boolean;
  nuevos_intentos int;
  nuevos_bloqueos int;
  segundos int;
  nuevo_bundle jsonb;
  nueva_sal text;
begin
  if p_tipo not in ('clave', 'respuesta') then
    return jsonb_build_object('ok', false, 'error', 'tipo inválido');
  end if;
  if p_usuario_id is null or length(p_usuario_id) > 100 or length(coalesce(p_valor, '')) > 200 then
    return jsonb_build_object('ok', false, 'error', 'datos inválidos');
  end if;

  -- Los intentos de una misma cuenta se procesan de a uno: sin esto, 50
  -- peticiones en paralelo leerían el mismo contador y probarían 50 claves.
  insert into public.intentos_credencial (usuario_id) values (p_usuario_id) on conflict do nothing;
  select * into fila from public.intentos_credencial where usuario_id = p_usuario_id for update;

  if fila.bloqueado_hasta is not null and fila.bloqueado_hasta > clock_timestamp() then
    return jsonb_build_object('ok', false, 'bloqueado', true,
      'segundos', ceil(extract(epoch from fila.bloqueado_hasta - clock_timestamp()))::int);
  end if;

  select * into cred from public.credenciales where usuario_id = p_usuario_id;
  bundle := case when p_tipo = 'clave' then cred.clave else cred.respuesta end;
  ok := public._verificar_bundle(bundle, p_valor);

  if ok then
    delete from public.intentos_credencial where usuario_id = p_usuario_id;
    if jsonb_typeof(bundle) = 'string' or (bundle ->> 'algo') is distinct from 'pbkdf2' then
      nueva_sal := encode(gen_random_bytes(16), 'hex');
      nuevo_bundle := jsonb_build_object(
        'algo', 'pbkdf2', 'sal', nueva_sal, 'iter', 100000,
        'valor', encode(public.pbkdf2_hmac_sha256(p_valor, nueva_sal, 100000), 'hex'));
      insert into public.credenciales (usuario_id, clave, respuesta)
        values (p_usuario_id,
                case when p_tipo = 'clave' then nuevo_bundle end,
                case when p_tipo = 'respuesta' then nuevo_bundle end)
      on conflict (usuario_id) do update
        set clave = case when p_tipo = 'clave' then nuevo_bundle else public.credenciales.clave end,
            respuesta = case when p_tipo = 'respuesta' then nuevo_bundle else public.credenciales.respuesta end,
            actualizado_en = clock_timestamp();
    end if;
    return jsonb_build_object('ok', true);
  end if;

  -- Los bloqueos previos se "olvidan" tras un día sin fallos.
  if fila.ultimo_fallo is not null and fila.ultimo_fallo < clock_timestamp() - interval '1 day' then
    fila.bloqueos := 0;
    fila.intentos := 0;
  end if;

  nuevos_intentos := coalesce(fila.intentos, 0) + 1;
  if nuevos_intentos >= 5 then
    nuevos_bloqueos := coalesce(fila.bloqueos, 0) + 1;
    segundos := case nuevos_bloqueos when 1 then 60 when 2 then 300 when 3 then 900 else 1800 end;
    update public.intentos_credencial
       set intentos = 0, bloqueos = nuevos_bloqueos, ultimo_fallo = clock_timestamp(),
           bloqueado_hasta = clock_timestamp() + make_interval(secs => segundos)
     where usuario_id = p_usuario_id;
    return jsonb_build_object('ok', false, 'bloqueado', true, 'segundos', segundos);
  end if;

  update public.intentos_credencial
     set intentos = nuevos_intentos, bloqueos = coalesce(fila.bloqueos, 0),
         ultimo_fallo = clock_timestamp(), bloqueado_hasta = null
   where usuario_id = p_usuario_id;
  return jsonb_build_object('ok', false, 'intentosRestantes', 5 - nuevos_intentos);
end;
$function$;

-- ---------------------------------------------------------------------------
-- 2) Límite por clave explícita (para la Edge Function, que conoce la IP real)
-- ---------------------------------------------------------------------------
create or replace function public.fn_limite_clave(p_clave text, p_max int, p_ventana_segundos int)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_conteo int;
begin
  perform pg_advisory_xact_lock(hashtext('limite:' || p_clave));
  select count(*) into v_conteo from limite_llamadas
   where clave = p_clave and creado_en > now() - make_interval(secs => p_ventana_segundos);
  if v_conteo >= p_max then return false; end if;
  insert into limite_llamadas (clave) values (p_clave);
  return true;
end;
$$;
revoke execute on function public.fn_limite_clave(text, int, int) from public, anon, authenticated;
grant  execute on function public.fn_limite_clave(text, int, int) to service_role;

-- La IP: lo que fija la infraestructura primero; el primer valor de
-- X-Forwarded-For lo puede escribir cualquiera, así que va al final.
create or replace function public.fn_identificador_llamador()
returns text
language plpgsql
stable
set search_path = public
as $$
declare
  v_headers json;
  v_ip text;
begin
  begin
    v_headers := current_setting('request.headers', true)::json;
  exception when others then
    v_headers := null;
  end;
  if v_headers is null then return 'sin-ip'; end if;
  v_ip := coalesce(
    nullif(trim(v_headers ->> 'cf-connecting-ip'), ''),
    nullif(trim(split_part(v_headers ->> 'x-forwarded-for', ',', 1)), ''));
  return coalesce(v_ip, 'sin-ip');
end;
$$;

-- ---------------------------------------------------------------------------
-- 3) Códigos de recuperación: un envío por código y límite por cuenta
-- ---------------------------------------------------------------------------
alter table public.recuperacion_codigos add column if not exists enviado boolean not null default false;

create or replace function public.rpc_generar_codigo_recuperacion(p_usuario_id text, p_canal text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_destino text;
  v_codigo text;
begin
  if not fn_verificar_limite('generar_codigo_recuperacion', 5, 300) then
    return jsonb_build_object('ok', false, 'motivo', 'limite_excedido');
  end if;
  -- además del límite por IP: 3 códigos cada 15 minutos por cuenta, para que
  -- nadie pueda llenar la casilla de otra persona rotando de IP
  if not public.fn_limite_clave('codigo:' || coalesce(p_usuario_id, ''), 3, 900) then
    return jsonb_build_object('ok', false, 'motivo', 'limite_excedido');
  end if;
  if p_canal not in ('email', 'sms') then
    return jsonb_build_object('ok', false, 'mensaje', 'Canal no válido.');
  end if;

  select case when p_canal = 'email' then email else telefono end into v_destino
  from contactos_recuperacion where usuario_id = p_usuario_id;
  if v_destino is null or v_destino = '' then
    return jsonb_build_object('ok', false, 'motivo', 'sin_contacto');
  end if;

  v_codigo := lpad(((('x' || encode(gen_random_bytes(4), 'hex'))::bit(32)::bigint) % 1000000)::text, 6, '0');

  update recuperacion_codigos set utilizado = true where usuario_id = p_usuario_id and utilizado = false;
  insert into recuperacion_codigos (usuario_id, canal, codigo) values (p_usuario_id, p_canal, v_codigo);
  return jsonb_build_object('ok', true);
end;
$$;

-- ---------------------------------------------------------------------------
-- 4) El límite de una cuenta también protege a los límites mismos
-- ---------------------------------------------------------------------------
-- fn_limite_clave y fn_verificar_limite escriben en limite_llamadas; la
-- limpieza periódica ya borra lo que tenga más de 1 hora, que cubre todas las
-- ventanas usadas (la más larga es de 15 minutos).
