-- ============================================================================
-- 007 · Recuperación de clave con código (OTP) por correo o SMS
-- ============================================================================
-- Decisión de diseño: el correo o teléfono de recuperación se registra desde
-- pantallas que ya exigen sesión (la admin para cualquier persona, o cada
-- persona para sí misma). La pantalla de "olvidé mi clave" nunca permite
-- escribir un destino nuevo: el código siempre va a la dirección guardada.
-- Si se pudiera escribir ahí, cualquiera elegiría a la admin, pondría su
-- propio correo y le cambiaría la clave.
--
-- El código se guarda en texto plano porque hay que poder leerlo una vez para
-- enviarlo. Lo protegen RLS (tabla sellada), el vencimiento de 10 minutos, un
-- solo uso, 4 intentos fallidos y el límite de llamadas.
--
-- El envío real lo hace la Edge Function despachar-otp (Resend o Twilio).
-- La migración 009 refuerza este flujo: registrar el contacto exige sesión y
-- el código se genera con un generador criptográfico.
-- ============================================================================

create table if not exists public.contactos_recuperacion (
  usuario_id text not null primary key,
  email text,
  telefono text,
  actualizado_en timestamptz not null default now()
);
alter table public.contactos_recuperacion enable row level security;

create table if not exists public.recuperacion_codigos (
  id uuid default gen_random_uuid() primary key,
  usuario_id text not null,
  canal text not null check (canal in ('email','sms')),
  codigo text not null,
  creado_en timestamptz not null default now(),
  expira_en timestamptz not null default (now() + interval '10 minutes'),
  intentos int not null default 0,
  utilizado boolean not null default false
);
alter table public.recuperacion_codigos enable row level security;
create index if not exists idx_recuperacion_codigos_usuario on public.recuperacion_codigos (usuario_id, creado_en desc);

create or replace function public.rpc_registrar_contacto_recuperacion(p_usuario_id text, p_canal text, p_destino text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_destino text := trim(p_destino);
begin
  if not fn_verificar_limite('registrar_contacto_recuperacion', 20, 300) then
    return jsonb_build_object('ok', false, 'motivo', 'limite_excedido');
  end if;
  if p_canal not in ('email','sms') then
    return jsonb_build_object('ok', false, 'mensaje', 'Canal no válido.');
  end if;
  if p_canal = 'email' then
    v_destino := lower(v_destino);
    if v_destino !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' then
      return jsonb_build_object('ok', false, 'mensaje', 'Correo no válido.');
    end if;
  else
    if length(regexp_replace(v_destino, '[^0-9]', '', 'g')) < 8 then
      return jsonb_build_object('ok', false, 'mensaje', 'Teléfono no válido.');
    end if;
  end if;

  insert into contactos_recuperacion (usuario_id, email, telefono)
    values (p_usuario_id, case when p_canal='email' then v_destino end, case when p_canal='sms' then v_destino end)
  on conflict (usuario_id) do update
    set email = case when p_canal='email' then v_destino else contactos_recuperacion.email end,
        telefono = case when p_canal='sms' then v_destino else contactos_recuperacion.telefono end,
        actualizado_en = now();
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.rpc_canales_disponibles(p_usuario_id text)
returns jsonb
language sql
security definer
set search_path = public
as $$
  select jsonb_build_object(
    'email', coalesce((select email is not null and email <> '' from contactos_recuperacion where usuario_id = p_usuario_id), false),
    'sms',   coalesce((select telefono is not null and telefono <> '' from contactos_recuperacion where usuario_id = p_usuario_id), false)
  );
$$;

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
  if p_canal not in ('email','sms') then
    return jsonb_build_object('ok', false, 'mensaje', 'Canal no válido.');
  end if;

  select case when p_canal='email' then email else telefono end into v_destino
  from contactos_recuperacion where usuario_id = p_usuario_id;

  if v_destino is null or v_destino = '' then
    return jsonb_build_object('ok', false, 'motivo', 'sin_contacto');
  end if;

  v_codigo := floor(100000 + random() * 900000)::text;

  update recuperacion_codigos set utilizado = true where usuario_id = p_usuario_id and utilizado = false;
  insert into recuperacion_codigos (usuario_id, canal, codigo)
    values (p_usuario_id, p_canal, v_codigo);

  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.rpc_verificar_codigo_recuperacion(p_usuario_id text, p_codigo text)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_rec record;
begin
  if not fn_verificar_limite('verificar_codigo_recuperacion', 20, 60) then
    return jsonb_build_object('ok', false, 'motivo', 'limite_excedido');
  end if;

  select * into v_rec from recuperacion_codigos
  where usuario_id = p_usuario_id and utilizado = false and expira_en > now()
  order by creado_en desc limit 1;

  if not found then
    return jsonb_build_object('ok', false, 'mensaje', 'El código expiró o no hay una solicitud activa.');
  end if;

  if v_rec.intentos >= 4 then
    update recuperacion_codigos set utilizado = true where id = v_rec.id;
    return jsonb_build_object('ok', false, 'mensaje', 'Demasiados intentos fallidos. Solicita un código nuevo.');
  end if;

  if v_rec.codigo <> trim(p_codigo) then
    update recuperacion_codigos set intentos = intentos + 1 where id = v_rec.id;
    return jsonb_build_object('ok', false, 'mensaje', 'Código incorrecto.', 'intentosRestantes', 4 - (v_rec.intentos + 1));
  end if;

  update recuperacion_codigos set utilizado = true where id = v_rec.id;
  return jsonb_build_object('ok', true);
end;
$$;

grant execute on function public.rpc_registrar_contacto_recuperacion(text, text, text) to anon, authenticated;
grant execute on function public.rpc_canales_disponibles(text) to anon, authenticated;
grant execute on function public.rpc_generar_codigo_recuperacion(text, text) to anon, authenticated;
grant execute on function public.rpc_verificar_codigo_recuperacion(text, text) to anon, authenticated;

create or replace function public.fn_limpiar_recuperacion_codigos()
returns void
language sql
security definer
set search_path = public
as $$
  delete from recuperacion_codigos where creado_en < now() - interval '1 day';
$$;
revoke execute on function public.fn_limpiar_recuperacion_codigos() from public, anon, authenticated;

do $$
begin
  if not exists (select 1 from cron.job where jobname = 'limpiar_recuperacion_codigos') then
    perform cron.schedule('limpiar_recuperacion_codigos', '*/30 * * * *', $cron$ select public.fn_limpiar_recuperacion_codigos(); $cron$);
  end if;
end $$;
