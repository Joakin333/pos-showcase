-- ============================================================================
-- 009 · Autenticación real: la base de datos deja de confiar en el navegador
-- ============================================================================
-- Requiere desplegar antes la Edge Function "iniciar-sesion" y el index.html
-- que la usa: con esta migración aplicada, nada se puede leer ni escribir sin
-- una sesión de Supabase Auth (salvo la lista de nombres del login).
--
-- EL PROBLEMA QUE CIERRA:
--   Hasta acá, el login, los roles (admin/vendedor) y la regla "el destino del
--   OTP solo lo cambia la admin" existían solo en index.html. La base aceptaba
--   cualquier llamada hecha con la llave publicable (que va dentro del propio
--   HTML), así que cualquiera podía, sin pasar por la app:
--     * cambiar la clave de cualquier persona, incluida la admin y el código
--       maestro (guardar_credencial no validaba quién llamaba y aceptaba un
--       bundle {"algo":"plano"} con la clave que quisiera);
--     * registrar SU correo como destino del OTP de otra persona
--       (rpc_registrar_contacto_recuperacion abierta a anon) y resetearle la clave;
--     * subirse a admin editando app_data.usuarios, reescribir stock, precios
--       y saldos de fiado, leer todos los clientes con sus deudas, e insertar
--       ventas falsas en el historial.
--
-- CÓMO LO CIERRA:
--   1) Cada persona entra con el mismo flujo de siempre (elige su nombre + clave),
--      pero la clave la valida la Edge Function "iniciar-sesion" con la llave de
--      servicio (verificar_credencial, con su bloqueo de 5 intentos) y, si es
--      correcta, entrega una sesión real de Supabase Auth. El JWT lleva
--      app_metadata.usuario_id, que solo puede escribir la llave de servicio.
--   2) El ROL nunca sale del JWT ni del navegador: fn_rol_actual() lo busca en
--      app_data.usuarios en cada consulta. Si la admin desactiva a alguien o le
--      cambia el rol, el efecto es inmediato, sin esperar a que venza un token.
--   3) app_data, ventas_registro y movimientos_registro pasan a exigir sesión.
--      Sin sesión solo se puede leer la lista de usuarios (la necesita la
--      pantalla de login para mostrar los nombres). La vendedora solo escribe
--      las claves que usa una venta o una caja; el resto, solo la admin.
--   4) Un trigger impide que alguien que no es admin cree o elimine usuarios o
--      cambie el rol / estado de cualquiera, aunque escriba directo por la API.
--   5) guardar_credencial / eliminar_credencial / registrar_contacto exigen
--      sesión y validan quién llama (admin, o la propia persona). Las claves
--      nuevas solo se aceptan en formato PBKDF2 (≥100.000 iteraciones).
--   6) Recuperar la clave (pregunta, código maestro u OTP) ya no son dos pasos
--      independientes ("validar" y después "guardar" sin prueba): la prueba y la
--      clave nueva viajan juntas a fn_restablecer_clave, que solo puede ejecutar
--      la Edge Function. Ya no existe un "guardar clave" sin autenticar.
--
-- QUÉ NO CAMBIA (se resuelve en la migración 010, registrar_venta):
--   la concurrencia de vender_stock / sincronización offline.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1) Quién llama y con qué rol
-- ---------------------------------------------------------------------------
create or replace function public.fn_usuario_actual()
returns text
language sql
stable
set search_path = public
as $$
  select nullif(auth.jwt() -> 'app_metadata' ->> 'usuario_id', '');
$$;

-- security definer: lee app_data aunque las políticas de abajo dependan de esta
-- misma función (sin esto, la política de app_data se llamaría a sí misma).
create or replace function public.fn_rol_actual()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select u ->> 'rol'
  from app_data d,
       jsonb_array_elements(case when jsonb_typeof(d.value) = 'array' then d.value else '[]'::jsonb end) u
  where d.key = 'usuarios'
    and public.fn_usuario_actual() is not null
    and u ->> 'id' = public.fn_usuario_actual()
    and coalesce(u ->> 'activo', 'true') <> 'false'
  limit 1;
$$;

create or replace function public.fn_es_admin()
returns boolean
language sql
stable
set search_path = public
as $$
  select coalesce(public.fn_rol_actual() = 'admin', false);
$$;

-- Qué claves de app_data puede escribir cada rol. La vendedora solo necesita
-- las que toca una venta (stock, lotes FIFO), la caja (turnos, retiros) y su
-- propio perfil en "usuarios" (el trigger de abajo limita qué puede cambiar ahí).
create or replace function public.fn_puede_escribir_clave(p_key text)
returns boolean
language sql
stable
set search_path = public
as $$
  select case public.fn_rol_actual()
    when 'admin' then true
    when 'vendedor' then p_key in ('productos', 'lotes', 'turnos', 'retiros', 'usuarios')
    else false
  end;
$$;

revoke execute on function public.fn_usuario_actual()            from public, anon;
revoke execute on function public.fn_rol_actual()                from public, anon;
revoke execute on function public.fn_es_admin()                  from public, anon;
revoke execute on function public.fn_puede_escribir_clave(text)  from public, anon;
grant  execute on function public.fn_usuario_actual()            to authenticated, service_role;
grant  execute on function public.fn_rol_actual()                to authenticated, service_role;
grant  execute on function public.fn_es_admin()                  to authenticated, service_role;
grant  execute on function public.fn_puede_escribir_clave(text)  to authenticated, service_role;

-- ---------------------------------------------------------------------------
-- 2) RLS: app_data y el historial exigen sesión
-- ---------------------------------------------------------------------------
-- Permisos de tabla mínimos (RLS filtra filas, pero el GRANT decide qué
-- comandos existen). Antes anon tenía todo, incluido TRUNCATE, que ignora RLS;
-- y authenticated no tenía nada, porque la app nunca había usado sesiones.
revoke all on table app_data, ventas_registro, movimientos_registro from anon, authenticated;
grant select                 on table app_data                              to anon;
grant select, insert, update on table app_data                              to authenticated;
grant select, insert         on table ventas_registro, movimientos_registro to authenticated;

drop policy if exists "app_data_select" on app_data;
drop policy if exists "app_data_insert" on app_data;
drop policy if exists "app_data_update" on app_data;
drop policy if exists "app_data_select_anon" on app_data;
drop policy if exists "app_data_select_auth" on app_data;

-- La pantalla de login necesita los nombres para que cada persona elija el suyo.
-- "usuarios" no lleva claves ni respuestas (viven en la tabla sellada credenciales).
create policy "app_data_select_anon" on app_data
  for select to anon
  using (key = 'usuarios');

create policy "app_data_select_auth" on app_data
  for select to authenticated
  using (key = 'usuarios' or (select public.fn_rol_actual()) is not null);

create policy "app_data_insert" on app_data
  for insert to authenticated
  with check (public.fn_puede_escribir_clave(key));

create policy "app_data_update" on app_data
  for update to authenticated
  using (public.fn_puede_escribir_clave(key))
  with check (public.fn_puede_escribir_clave(key));

drop policy if exists "ventas_registro_select" on ventas_registro;
drop policy if exists "ventas_registro_insert" on ventas_registro;
create policy "ventas_registro_select" on ventas_registro
  for select to authenticated using ((select public.fn_rol_actual()) is not null);
create policy "ventas_registro_insert" on ventas_registro
  for insert to authenticated with check ((select public.fn_rol_actual()) is not null);

drop policy if exists "movimientos_registro_select" on movimientos_registro;
drop policy if exists "movimientos_registro_insert" on movimientos_registro;
create policy "movimientos_registro_select" on movimientos_registro
  for select to authenticated using ((select public.fn_rol_actual()) is not null);
create policy "movimientos_registro_insert" on movimientos_registro
  for insert to authenticated with check ((select public.fn_rol_actual()) is not null);

-- ---------------------------------------------------------------------------
-- 3) Nadie que no sea admin puede crear/eliminar usuarios ni cambiar roles
-- ---------------------------------------------------------------------------
create or replace function public.fn_proyeccion_usuarios(p jsonb)
returns jsonb
language sql
immutable
as $$
  select coalesce(
    jsonb_agg(jsonb_build_object('id', u ->> 'id', 'rol', u ->> 'rol', 'activo', coalesce(u ->> 'activo', 'true'))
              order by u ->> 'id'),
    '[]'::jsonb)
  from jsonb_array_elements(case when jsonb_typeof(p) = 'array' then p else '[]'::jsonb end) u;
$$;

-- SECURITY INVOKER a propósito: current_user tiene que ser el rol de quien llama
-- (anon/authenticated por la API). Las funciones security definer de este
-- archivo (siembra inicial) corren como su dueño y no pasan por esta regla.
create or replace function public.fn_proteger_usuarios()
returns trigger
language plpgsql
set search_path = public
as $$
begin
  if NEW.key <> 'usuarios' then return NEW; end if;
  if current_user not in ('anon', 'authenticated') then return NEW; end if;
  if public.fn_es_admin() then return NEW; end if;
  if TG_OP = 'INSERT'
     or public.fn_proyeccion_usuarios(OLD.value) is distinct from public.fn_proyeccion_usuarios(NEW.value) then
    raise exception 'Solo una administradora puede crear o eliminar usuarios o cambiar su rol.'
      using errcode = '42501';
  end if;
  return NEW;
end;
$$;

drop trigger if exists trg_proteger_usuarios on app_data;
create trigger trg_proteger_usuarios
before insert or update on app_data
for each row execute function public.fn_proteger_usuarios();

-- ---------------------------------------------------------------------------
-- 4) Credenciales
-- ---------------------------------------------------------------------------
-- Solo se aceptan claves nuevas en PBKDF2 con sal propia. Antes se aceptaba
-- {"algo":"plano","valor":"..."}: quien llamara podía fijar una clave conocida.
create or replace function public._bundle_valido(p jsonb)
returns boolean
language plpgsql
immutable
as $$
begin
  if p is null or jsonb_typeof(p) <> 'object' then return false; end if;
  if p ->> 'algo' is distinct from 'pbkdf2' then return false; end if;
  if coalesce(p ->> 'sal', '') !~ '^[0-9a-f]{32,128}$' then return false; end if;
  if coalesce(p ->> 'valor', '') !~ '^[0-9a-f]{64}$' then return false; end if;
  if coalesce(p ->> 'iter', '') !~ '^[0-9]{6,7}$' then return false; end if;
  return (p ->> 'iter')::int between 100000 and 1000000;
end;
$$;
revoke execute on function public._bundle_valido(jsonb) from public, anon, authenticated;

create or replace function public.guardar_credencial(p_usuario_id text, p_tipo text, p_valor_nuevo jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_yo text := public.fn_usuario_actual();
  v_admin boolean := public.fn_es_admin();
begin
  if public.fn_rol_actual() is null then
    return jsonb_build_object('ok', false, 'mensaje', 'Necesitas iniciar sesión.');
  end if;
  if p_tipo not in ('clave', 'respuesta') then
    return jsonb_build_object('ok', false, 'mensaje', 'Tipo inválido.');
  end if;
  -- la admin puede cambiar cualquier credencial (incluido el código maestro);
  -- cualquier otra persona, solo las suyas.
  if not v_admin and (p_usuario_id is distinct from v_yo or p_usuario_id = '__maestro__') then
    return jsonb_build_object('ok', false, 'mensaje', 'No tienes permiso para cambiar esa credencial.');
  end if;
  if p_valor_nuevo is null and p_tipo = 'clave' then
    return jsonb_build_object('ok', false, 'mensaje', 'La clave no puede quedar vacía.');
  end if;
  if p_valor_nuevo is not null and not public._bundle_valido(p_valor_nuevo) then
    return jsonb_build_object('ok', false, 'mensaje', 'Formato de clave no válido.');
  end if;

  insert into public.credenciales(usuario_id, clave, respuesta)
    values (
      p_usuario_id,
      case when p_tipo = 'clave' then p_valor_nuevo end,
      case when p_tipo = 'respuesta' then p_valor_nuevo end
    )
  on conflict (usuario_id) do update
    set clave = case when p_tipo = 'clave' then p_valor_nuevo else public.credenciales.clave end,
        respuesta = case when p_tipo = 'respuesta' then p_valor_nuevo else public.credenciales.respuesta end,
        actualizado_en = now();
  delete from public.intentos_credencial where usuario_id = p_usuario_id;
  return jsonb_build_object('ok', true);
end;
$$;

create or replace function public.eliminar_credencial(p_usuario_id text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.fn_es_admin() or p_usuario_id = '__maestro__' then
    return jsonb_build_object('ok', false, 'mensaje', 'Solo una administradora puede eliminar credenciales.');
  end if;
  delete from public.credenciales where usuario_id = p_usuario_id;
  delete from public.intentos_credencial where usuario_id = p_usuario_id;
  delete from public.contactos_recuperacion where usuario_id = p_usuario_id;
  return jsonb_build_object('ok', true);
end;
$$;

revoke execute on function public.guardar_credencial(text, text, jsonb) from public, anon;
revoke execute on function public.eliminar_credencial(text)             from public, anon;
grant  execute on function public.guardar_credencial(text, text, jsonb) to authenticated;
grant  execute on function public.eliminar_credencial(text)             to authenticated;

-- verificar_credencial sigue abierta: la pantalla de recuperación la usa para
-- validar la respuesta / el código maestro antes de pedir la clave nueva, y
-- tiene su propio bloqueo de 5 intentos. Validar ya no da acceso a nada: la
-- sesión solo la entrega la Edge Function y el cambio de clave sin sesión solo
-- ocurre en fn_restablecer_clave, que vuelve a exigir la prueba.
grant execute on function public.verificar_credencial(text, text, text) to service_role;

-- ---------------------------------------------------------------------------
-- 5) Siembra inicial (instalación nueva, sin usuarios todavía)
-- ---------------------------------------------------------------------------
-- Antes se hacía con guardar_credencial sin sesión. Ahora es una sola llamada
-- que solo funciona mientras el negocio no tenga NINGÚN usuario ni credencial.
create or replace function public.rpc_sembrar_inicial(p_usuarios jsonb, p_credenciales jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_c jsonb;
  v_ids text[];
begin
  -- serializa siembras simultáneas desde dos dispositivos recién abiertos
  perform pg_advisory_xact_lock(hashtext('rpc_sembrar_inicial'));

  if exists (select 1 from app_data where key = 'usuarios'
             and jsonb_typeof(value) = 'array' and jsonb_array_length(value) > 0)
     or exists (select 1 from credenciales where usuario_id <> '__maestro__') then
    return jsonb_build_object('ok', false, 'motivo', 'ya_inicializado');
  end if;
  if jsonb_typeof(p_usuarios) <> 'array' or jsonb_array_length(p_usuarios) = 0
     or jsonb_typeof(p_credenciales) <> 'array' then
    return jsonb_build_object('ok', false, 'mensaje', 'Datos inválidos.');
  end if;
  select array_agg(u ->> 'id') into v_ids from jsonb_array_elements(p_usuarios) u;
  if not exists (select 1 from jsonb_array_elements(p_usuarios) u where u ->> 'rol' = 'admin') then
    return jsonb_build_object('ok', false, 'mensaje', 'Debe haber al menos una administradora.');
  end if;

  for v_c in select * from jsonb_array_elements(p_credenciales) loop
    if not (v_c ->> 'usuario_id' = any(v_ids))
       or v_c ->> 'tipo' not in ('clave', 'respuesta')
       or not public._bundle_valido(v_c -> 'bundle') then
      return jsonb_build_object('ok', false, 'mensaje', 'Credencial inválida.');
    end if;
    insert into credenciales (usuario_id, clave, respuesta)
      values (v_c ->> 'usuario_id',
              case when v_c ->> 'tipo' = 'clave' then v_c -> 'bundle' end,
              case when v_c ->> 'tipo' = 'respuesta' then v_c -> 'bundle' end)
    on conflict (usuario_id) do update
      set clave = coalesce(excluded.clave, credenciales.clave),
          respuesta = coalesce(excluded.respuesta, credenciales.respuesta),
          actualizado_en = now();
  end loop;

  insert into app_data (key, value, updated_at) values ('usuarios', p_usuarios, now())
  on conflict (key) do update set value = excluded.value, updated_at = excluded.updated_at;
  return jsonb_build_object('ok', true);
end;
$$;
revoke execute on function public.rpc_sembrar_inicial(jsonb, jsonb) from public;
grant  execute on function public.rpc_sembrar_inicial(jsonb, jsonb) to anon, authenticated;

-- ---------------------------------------------------------------------------
-- 6) Recuperación de clave: la prueba y la clave nueva van juntas
-- ---------------------------------------------------------------------------
-- Valida el código sin consumirlo (la pantalla lo usa para avanzar al paso de
-- "clave nueva"); el que lo consume es fn_restablecer_clave. FOR UPDATE: dos
-- intentos simultáneos ya no pueden leer el mismo contador de intentos.
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
  order by creado_en desc limit 1
  for update;

  if not found then
    return jsonb_build_object('ok', false, 'mensaje', 'El código expiró o no hay una solicitud activa.');
  end if;
  if v_rec.intentos >= 4 then
    update recuperacion_codigos set utilizado = true where id = v_rec.id;
    return jsonb_build_object('ok', false, 'mensaje', 'Demasiados intentos fallidos. Solicita un código nuevo.');
  end if;
  if v_rec.codigo <> trim(coalesce(p_codigo, '')) then
    update recuperacion_codigos set intentos = intentos + 1 where id = v_rec.id;
    return jsonb_build_object('ok', false, 'mensaje', 'Código incorrecto.', 'intentosRestantes', 4 - (v_rec.intentos + 1));
  end if;
  return jsonb_build_object('ok', true);
end;
$$;

-- El código ahora sale de un generador criptográfico (antes: random()).
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

-- Solo la Edge Function "iniciar-sesion" (llave de servicio) puede ejecutarla.
create or replace function public.fn_restablecer_clave(p_usuario_id text, p_metodo text, p_prueba text, p_bundle jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public, extensions
as $$
declare
  v_r jsonb;
  v_rec record;
  v_es_admin boolean;
begin
  if not public._bundle_valido(p_bundle) then
    return jsonb_build_object('ok', false, 'mensaje', 'Formato de clave no válido.');
  end if;
  if p_usuario_id is null or p_usuario_id = '__maestro__' then
    return jsonb_build_object('ok', false, 'mensaje', 'Usuario no válido.');
  end if;

  if p_metodo = 'respuesta' then
    v_r := public.verificar_credencial(p_usuario_id, 'respuesta', p_prueba);
    if not coalesce((v_r ->> 'ok')::boolean, false) then return v_r; end if;

  elsif p_metodo = 'maestro' then
    select exists (
      select 1 from app_data d, jsonb_array_elements(d.value) u
      where d.key = 'usuarios' and u ->> 'id' = p_usuario_id and u ->> 'rol' = 'admin'
    ) into v_es_admin;
    if not v_es_admin then
      return jsonb_build_object('ok', false, 'mensaje', 'El código maestro solo sirve para una administradora.');
    end if;
    v_r := public.verificar_credencial('__maestro__', 'clave', p_prueba);
    if not coalesce((v_r ->> 'ok')::boolean, false) then return v_r; end if;

  elsif p_metodo = 'otp' then
    select * into v_rec from recuperacion_codigos
    where usuario_id = p_usuario_id and utilizado = false and expira_en > now()
    order by creado_en desc limit 1
    for update;
    if not found then
      return jsonb_build_object('ok', false, 'mensaje', 'El código expiró o no hay una solicitud activa.');
    end if;
    if v_rec.intentos >= 4 then
      update recuperacion_codigos set utilizado = true where id = v_rec.id;
      return jsonb_build_object('ok', false, 'mensaje', 'Demasiados intentos fallidos. Solicita un código nuevo.');
    end if;
    if v_rec.codigo <> trim(coalesce(p_prueba, '')) then
      update recuperacion_codigos set intentos = intentos + 1 where id = v_rec.id;
      return jsonb_build_object('ok', false, 'mensaje', 'Código incorrecto.');
    end if;
    update recuperacion_codigos set utilizado = true where id = v_rec.id;

  else
    return jsonb_build_object('ok', false, 'mensaje', 'Método no válido.');
  end if;

  insert into credenciales (usuario_id, clave) values (p_usuario_id, p_bundle)
  on conflict (usuario_id) do update set clave = excluded.clave, actualizado_en = now();
  delete from intentos_credencial where usuario_id = p_usuario_id;
  return jsonb_build_object('ok', true);
end;
$$;
revoke execute on function public.fn_restablecer_clave(text, text, text, jsonb) from public, anon, authenticated;
grant  execute on function public.fn_restablecer_clave(text, text, text, jsonb) to service_role;

-- Registrar el correo/teléfono de recuperación: solo la admin, o la propia persona.
create or replace function public.rpc_registrar_contacto_recuperacion(p_usuario_id text, p_canal text, p_destino text)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_destino text := trim(p_destino);
begin
  if not (public.fn_es_admin() or (public.fn_rol_actual() is not null and p_usuario_id = public.fn_usuario_actual())) then
    return jsonb_build_object('ok', false, 'mensaje', 'No tienes permiso para cambiar ese contacto.');
  end if;
  if not fn_verificar_limite('registrar_contacto_recuperacion', 20, 300) then
    return jsonb_build_object('ok', false, 'motivo', 'limite_excedido');
  end if;
  if p_canal not in ('email', 'sms') then
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
    values (p_usuario_id, case when p_canal = 'email' then v_destino end, case when p_canal = 'sms' then v_destino end)
  on conflict (usuario_id) do update
    set email = case when p_canal = 'email' then v_destino else contactos_recuperacion.email end,
        telefono = case when p_canal = 'sms' then v_destino else contactos_recuperacion.telefono end,
        actualizado_en = now();
  return jsonb_build_object('ok', true);
end;
$$;
revoke execute on function public.rpc_registrar_contacto_recuperacion(text, text, text) from public, anon;
grant  execute on function public.rpc_registrar_contacto_recuperacion(text, text, text) to authenticated;

-- ---------------------------------------------------------------------------
-- 7) Resto de RPC que la app usa con sesión
-- ---------------------------------------------------------------------------
revoke execute on function public.vender_stock(jsonb) from public, anon;
grant  execute on function public.vender_stock(jsonb) to authenticated;

revoke execute on function public.fn_verificar_limite(text, int, int) from public, anon;
grant  execute on function public.fn_verificar_limite(text, int, int) to authenticated;

-- Avisos push de venta: solo la admin suscribe un dispositivo (antes, cualquiera
-- podía registrar su propio endpoint y recibir el aviso de cada venta).
create or replace function public.guardar_suscripcion_push(p_endpoint text, p_p256dh text, p_auth text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.fn_es_admin() then
    raise exception 'Solo una administradora puede activar los avisos de venta.' using errcode = '42501';
  end if;
  if not fn_verificar_limite('guardar_suscripcion_push', 10, 60) then
    raise exception 'Demasiados intentos, espera un momento.';
  end if;
  insert into push_suscripciones (endpoint, p256dh, auth)
  values (p_endpoint, p_p256dh, p_auth)
  on conflict (endpoint) do update set p256dh = excluded.p256dh, auth = excluded.auth, creado_en = now();
end;
$$;
revoke execute on function public.guardar_suscripcion_push(text, text, text) from public, anon;
grant  execute on function public.guardar_suscripcion_push(text, text, text) to authenticated;
revoke execute on function public.eliminar_suscripcion_push(text) from public, anon;
grant  execute on function public.eliminar_suscripcion_push(text) to authenticated;

-- search_path fijo en las dos funciones auxiliares (advertencia
-- "function_search_path_mutable" del linter de Supabase)
alter function public.fn_proyeccion_usuarios(jsonb) set search_path = '';
alter function public._bundle_valido(jsonb) set search_path = '';

-- ============================================================================
-- Verificación rápida (como anon, desde el SQL Editor):
--   set role anon;
--   select key from app_data;                                   -- solo 'usuarios'
--   select guardar_credencial('x','clave','{}'::jsonb);          -- permission denied
--   update app_data set value = '[]' where key = 'productos';   -- UPDATE 0
--   reset role;
-- ============================================================================
