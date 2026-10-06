-- ============================================================================
-- 012 · Mínimo privilegio: cada rol ve y escribe solo lo que necesita
-- ============================================================================
-- Hallazgos de una auditoría hecha atacando el sistema desplegado:
--
--   1) Una vendedora podía leer por la API TODO el negocio: costos de los
--      lotes, clientes con sus deudas y la utilidad de cada venta. La interfaz
--      se lo ocultaba, pero la base no.
--   2) Una vendedora podía INSERTAR filas en el historial (ventas y
--      movimientos falsos) y hasta ocupar el id de una venta futura.
--   3) Una vendedora podía cambiar la pregunta de seguridad de la admin.
--   4) Las tablas selladas más nuevas daban a anon y authenticated TODOS los
--      permisos (solo las protegía RLS sin políticas).
--   5) El registro público de Supabase Auth estaba abierto: cualquiera con la
--      llave publicable podía crear cuentas (y disparar correos de confirmación).
--   6) registrar_venta buscaba los movimientos de una venta repetida con LIKE,
--      pero "_" (válido en un id) es un comodín.
--   7) En una base creada desde cero, pbkdf2_hmac_sha256 era ejecutable por
--      anon: cualquiera podía agotar la CPU de la base pidiéndole millones de
--      iteraciones (en una base antigua ya estaba cerrada a mano).
--
-- Después de esta migración:
--   · la administradora ve todo;
--   · la vendedora lee solo el catálogo, los turnos, los retiros, la lista de
--     personas y las ventas de SU turno abierto; no lee lotes, clientes ni
--     movimientos, y no puede escribir en el historial;
--   · las tablas selladas no tienen ningún permiso para anon ni authenticated;
--   · las cuentas de Auth solo se crean desde la Edge Function iniciar-sesion.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1) Tablas selladas: sin permisos de tabla (antes, solo las protegía RLS)
-- ---------------------------------------------------------------------------
revoke all on table
  public.credenciales, public.credenciales_usuario, public.intentos_credencial,
  public.intentos_login, public.limite_llamadas, public.respaldos_app_data,
  public.push_suscripciones, public.contactos_recuperacion, public.recuperacion_codigos
from anon, authenticated;

-- Funciones internas que no tienen por qué poder llamarse desde la API.
-- pbkdf2_hmac_sha256 y _verificar_bundle quedaban ejecutables por cualquiera en una
-- base creada desde cero (en una base antigua ya estaban cerradas a mano). Llamar a
-- pbkdf2_hmac_sha256 con millones de iteraciones agota la CPU de la base: lo encontró la
-- prueba de contrato de la API al correr sobre una instalación nueva.
revoke execute on function public.pbkdf2_hmac_sha256(text, text, integer) from public, anon, authenticated;
revoke execute on function public._verificar_bundle(jsonb, text)          from public, anon, authenticated;
revoke execute on function public.fn_identificador_llamador() from public, anon, authenticated;
revoke execute on function public.fn_proteger_usuarios()      from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- 2) Qué ve cada rol
-- ---------------------------------------------------------------------------
-- Inicio del turno abierto: la vendedora solo ve las ventas desde ese momento.
create or replace function public.fn_inicio_turno_abierto()
returns timestamptz
language sql
stable
security definer
set search_path = public
as $$
  select max(to_timestamp((t ->> 'fechaApertura')::numeric / 1000.0))
  from app_data d,
       jsonb_array_elements(case when jsonb_typeof(d.value) = 'array' then d.value else '[]'::jsonb end) t
  where d.key = 'turnos' and t ->> 'estado' = 'abierto' and (t ->> 'fechaApertura') ~ '^[0-9]+$';
$$;
revoke execute on function public.fn_inicio_turno_abierto() from public, anon;
grant  execute on function public.fn_inicio_turno_abierto() to authenticated, service_role;

drop policy if exists "app_data_select_auth" on public.app_data;
create policy "app_data_select_auth" on public.app_data
  for select to authenticated
  using (
    key = 'usuarios'
    or (select public.fn_es_admin())
    or (key in ('productos', 'productos_padre', 'turnos', 'retiros') and (select public.fn_rol_actual()) = 'vendedor')
  );

drop policy if exists "ventas_registro_select" on public.ventas_registro;
create policy "ventas_registro_select" on public.ventas_registro
  for select to authenticated
  using (
    (select public.fn_es_admin())
    or ((select public.fn_rol_actual()) is not null and creado_en >= (select public.fn_inicio_turno_abierto()))
  );

drop policy if exists "movimientos_registro_select" on public.movimientos_registro;
create policy "movimientos_registro_select" on public.movimientos_registro
  for select to authenticated using ((select public.fn_es_admin()));

-- ---------------------------------------------------------------------------
-- 3) Quién escribe el historial: la vendedora, nadie directo
-- ---------------------------------------------------------------------------
-- Sus ventas entran por registrar_venta (security definer). Los abonos y los
-- movimientos de entrada de stock los hace la administradora.
drop policy if exists "ventas_registro_insert" on public.ventas_registro;
create policy "ventas_registro_insert" on public.ventas_registro
  for insert to authenticated with check ((select public.fn_es_admin()));

drop policy if exists "movimientos_registro_insert" on public.movimientos_registro;
create policy "movimientos_registro_insert" on public.movimientos_registro
  for insert to authenticated with check ((select public.fn_es_admin()));

-- ---------------------------------------------------------------------------
-- 4) La lista de personas: cada una edita solo lo suyo
-- ---------------------------------------------------------------------------
-- Una persona que no es administradora solo puede cambiar su propia pregunta de
-- seguridad. Todo lo demás (otros perfiles, nombres, roles, estado) queda igual.
create or replace function public.fn_normalizar_usuarios(p jsonb, p_yo text)
returns jsonb
language sql
immutable
set search_path = ''
as $$
  select coalesce(jsonb_agg(
           case when u ->> 'id' = p_yo then u - 'pregunta' - 'tieneRespuesta' - 'actualizadoEn'
                else u - 'actualizadoEn' end
           order by u ->> 'id'), '[]'::jsonb)
  from jsonb_array_elements(case when jsonb_typeof(p) = 'array' then p else '[]'::jsonb end) u;
$$;
revoke execute on function public.fn_normalizar_usuarios(jsonb, text) from public, anon;
grant  execute on function public.fn_normalizar_usuarios(jsonb, text) to authenticated;

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
     or public.fn_normalizar_usuarios(OLD.value, public.fn_usuario_actual())
        is distinct from public.fn_normalizar_usuarios(NEW.value, public.fn_usuario_actual()) then
    raise exception 'Solo una administradora puede crear o eliminar personas, cambiar roles o editar a otras personas.'
      using errcode = '42501';
  end if;
  return NEW;
end;
$$;
drop function if exists public.fn_proyeccion_usuarios(jsonb);

-- avisos push: solo la administradora (consistente con guardar_suscripcion_push)
create or replace function public.eliminar_suscripcion_push(p_endpoint text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not public.fn_es_admin() then
    raise exception 'Solo una administradora puede desactivar los avisos de venta.' using errcode = '42501';
  end if;
  delete from push_suscripciones where endpoint = p_endpoint;
end;
$$;

-- una fila vacía que quedó de una versión anterior
delete from public.app_data where key = 'auth_config' and value = '{}'::jsonb;

-- ---------------------------------------------------------------------------
-- 5) Registro público de Auth cerrado también en la base
-- ---------------------------------------------------------------------------
-- Además de desactivarlo en el panel (Authentication → Providers → Email), la
-- base rechaza toda cuenta cuyo correo no sea del dominio interno reservado
-- (.invalid, RFC 2606) que usa la Edge Function iniciar-sesion. Un registro
-- público trae un correo real, así que queda fuera. (No se puede exigir el
-- usuario_id en app_metadata: GoTrue lo escribe después de insertar la fila.)
create or replace function public.fn_bloquear_registro_publico()
returns trigger
language plpgsql
set search_path = ''
as $$
begin
  if lower(coalesce(new.email, '')) not like '%@usuarios.pos.invalid' then
    raise exception 'El registro público está desactivado.' using errcode = '42501';
  end if;
  return new;
end;
$$;
revoke execute on function public.fn_bloquear_registro_publico() from public, anon, authenticated;

do $$
begin
  if to_regclass('auth.users') is not null then
    drop trigger if exists trg_bloquear_registro_publico on auth.users;
    create trigger trg_bloquear_registro_publico
      before insert on auth.users
      for each row execute function public.fn_bloquear_registro_publico();
  end if;
end $$;

-- ---------------------------------------------------------------------------
-- 6) registrar_venta: sin LIKE, y la vendedora no recibe costos ni clientes
-- ---------------------------------------------------------------------------
create or replace function public.registrar_venta(p_venta jsonb, p_offline boolean default false)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_rol text := public.fn_rol_actual();
  v_id text := p_venta ->> 'id';
  v_fecha numeric;
  v_items jsonb;
  v_pagos jsonb := coalesce(p_venta -> 'pagos', '[]'::jsonb);
  v_productos jsonb;
  v_lotes jsonb;
  v_clientes jsonb;
  v_lotes_cambiaron boolean := false;
  v_item jsonb;
  v_idx int;
  v_stock numeric;
  v_cant numeric;
  v_precio_fallback numeric;
  v_fifo jsonb;
  v_costo numeric;
  v_items_final jsonb := '[]'::jsonb;
  v_faltantes jsonb := '[]'::jsonb;
  v_revision jsonb := '[]'::jsonb;
  v_total numeric := 0;
  v_costo_total numeric := 0;
  v_monto_fiado numeric := 0;
  v_cliente_id text := nullif(p_venta ->> 'clienteId', '');
  v_cidx int;
  v_venta jsonb;
  v_movimientos jsonb := '[]'::jsonb;
  v_mov jsonb;
  v_n int := 0;
begin
  if v_rol is null then
    return jsonb_build_object('ok', false, 'motivo', 'sin_sesion');
  end if;

  -- ---- validación (antes de bloquear nada) --------------------------------
  if v_id is null or v_id !~ '^[A-Za-z0-9_-]{4,64}$' then
    return jsonb_build_object('ok', false, 'motivo', 'datos_invalidos', 'mensaje', 'Id de venta inválido.');
  end if;
  if jsonb_typeof(p_venta -> 'items') is distinct from 'array' or jsonb_array_length(p_venta -> 'items') = 0 then
    return jsonb_build_object('ok', false, 'motivo', 'datos_invalidos', 'mensaje', 'La venta no tiene productos.');
  end if;
  if exists (
    select 1 from jsonb_array_elements(p_venta -> 'items') e
    where coalesce(e ->> 'productoId', '') = ''
       or not public._es_numero(e ->> 'cantidad')
       or not public._es_numero(e ->> 'precioUnitario')
  ) or exists (
    select 1 from jsonb_array_elements(p_venta -> 'items') e
    where (e ->> 'cantidad')::numeric <= 0
  ) then
    return jsonb_build_object('ok', false, 'motivo', 'datos_invalidos', 'mensaje', 'Cantidad o precio inválido.');
  end if;
  if jsonb_typeof(v_pagos) <> 'array' or exists (
    select 1 from jsonb_array_elements(v_pagos) pg
    where coalesce(pg ->> 'metodo', '') not in ('efectivo', 'debito', 'credito', 'transferencia', 'fiado')
       or not public._es_numero(pg ->> 'monto')
  ) then
    return jsonb_build_object('ok', false, 'motivo', 'datos_invalidos', 'mensaje', 'Forma de pago inválida.');
  end if;
  -- fiado y transferencia son solo de la administradora (igual que en la interfaz)
  if v_rol <> 'admin' and exists (
    select 1 from jsonb_array_elements(v_pagos) pg where pg ->> 'metodo' in ('fiado', 'transferencia')
  ) then
    return jsonb_build_object('ok', false, 'motivo', 'no_permitido', 'mensaje', 'Ese medio de pago no está habilitado para tu usuario.');
  end if;
  select coalesce(sum((pg ->> 'monto')::numeric), 0) into v_monto_fiado
  from jsonb_array_elements(v_pagos) pg where pg ->> 'metodo' = 'fiado';
  if v_monto_fiado > 0 and v_cliente_id is null then
    return jsonb_build_object('ok', false, 'motivo', 'datos_invalidos', 'mensaje', 'Un fiado necesita un cliente.');
  end if;

  v_fecha := case when public._es_numero(p_venta ->> 'fecha') then (p_venta ->> 'fecha')::numeric
                  else extract(epoch from now()) * 1000 end;

  -- Líneas repetidas del mismo producto se agrupan (en el orden en que aparecen).
  select jsonb_agg(jsonb_build_object(
           'productoId', x.pid, 'nombre', x.nombre,
           'cantidad', x.cant, 'precioUnitario', x.precio) order by x.primera)
  into v_items
  from (
    select e ->> 'productoId' as pid,
           min(t.ord) as primera,
           sum((e ->> 'cantidad')::numeric) as cant,
           (array_agg(e ->> 'nombre' order by t.ord))[1] as nombre,
           (array_agg((e ->> 'precioUnitario')::numeric order by t.ord))[1] as precio
    from jsonb_array_elements(p_venta -> 'items') with ordinality as t(e, ord)
    group by e ->> 'productoId'
  ) x;

  if not public.fn_verificar_limite('registrar_venta', 120, 60) then
    return jsonb_build_object('ok', false, 'motivo', 'limite_excedido');
  end if;

  -- ---- bloqueo: a partir de aquí, las ventas van en fila -------------------
  select value into v_productos from app_data where key = 'productos' for update;
  if v_productos is null then
    return jsonb_build_object('ok', false, 'motivo', 'sin_catalogo');
  end if;

  -- ---- idempotencia: ¿esta venta ya se registró? ----------------------------
  -- Se revisa DESPUÉS de tomar el bloqueo: si dos reintentos de la misma venta
  -- llegan juntos, el segundo espera al primero y aquí ya la encuentra.
  select data into v_venta from ventas_registro where id = v_id;
  if found then
    select coalesce(jsonb_agg(data order by id), '[]'::jsonb) into v_movimientos
    from movimientos_registro where data ->> 'ventaId' = v_id;
    select value into v_lotes from app_data where key = 'lotes';
    select value into v_clientes from app_data where key = 'clientes';
    return jsonb_build_object('ok', true, 'duplicada', true, 'venta', v_venta,
      'movimientos', v_movimientos, 'productos', v_productos,
      'lotes', case when v_rol = 'admin' then coalesce(v_lotes, '[]'::jsonb) end,
      'clientes', case when v_rol = 'admin' then coalesce(v_clientes, '[]'::jsonb) end);
  end if;

  select value into v_lotes from app_data where key = 'lotes' for update;
  v_lotes := coalesce(v_lotes, '[]'::jsonb);

  -- ---- stock: revisar todo antes de tocar nada ------------------------------
  for v_item in select * from jsonb_array_elements(v_items) loop
    v_cant := (v_item ->> 'cantidad')::numeric;
    select (t.ord - 1)::int into v_idx
    from jsonb_array_elements(v_productos) with ordinality as t(elem, ord)
    where t.elem ->> 'id' = v_item ->> 'productoId' limit 1;

    if v_idx is null then
      if p_offline then
        v_revision := v_revision || jsonb_build_object('productoId', v_item ->> 'productoId', 'motivo', 'no_existe');
      else
        v_faltantes := v_faltantes || jsonb_build_object('productoId', v_item ->> 'productoId', 'motivo', 'no_existe');
      end if;
      continue;
    end if;
    v_stock := coalesce((v_productos -> v_idx ->> 'stock')::numeric, 0);
    if v_stock < v_cant then
      if p_offline then
        v_revision := v_revision || jsonb_build_object('productoId', v_item ->> 'productoId',
          'motivo', 'stock_insuficiente', 'stockAntes', v_stock, 'cantidad', v_cant);
      else
        v_faltantes := v_faltantes || jsonb_build_object('productoId', v_item ->> 'productoId',
          'motivo', 'stock_insuficiente', 'stockActual', v_stock);
      end if;
    end if;
  end loop;

  if jsonb_array_length(v_faltantes) > 0 then
    return jsonb_build_object('ok', false, 'motivo', 'stock_insuficiente', 'faltantes', v_faltantes);
  end if;

  -- ---- aplicar: stock, lotes FIFO y costo ----------------------------------
  for v_item in select * from jsonb_array_elements(v_items) loop
    v_cant := (v_item ->> 'cantidad')::numeric;
    v_n := v_n + 1;
    select (t.ord - 1)::int into v_idx
    from jsonb_array_elements(v_productos) with ordinality as t(elem, ord)
    where t.elem ->> 'id' = v_item ->> 'productoId' limit 1;

    v_precio_fallback := (v_item ->> 'precioUnitario')::numeric;
    if v_idx is not null then
      v_stock := coalesce((v_productos -> v_idx ->> 'stock')::numeric, 0);
      v_productos := jsonb_set(v_productos, array[v_idx::text, 'stock'], to_jsonb(v_stock - v_cant));
      v_precio_fallback := coalesce((v_productos -> v_idx ->> 'precio')::numeric, v_precio_fallback);
    end if;

    v_fifo := public._consumir_fifo(v_lotes, v_item ->> 'productoId', v_cant, v_precio_fallback);
    if v_fifo -> 'lotes' is distinct from v_lotes then v_lotes_cambiaron := true; end if;
    v_lotes := v_fifo -> 'lotes';
    v_costo := (v_fifo ->> 'costo')::numeric;

    v_items_final := v_items_final || (v_item || jsonb_build_object('costoTotal', v_costo));
    v_total := v_total + v_cant * (v_item ->> 'precioUnitario')::numeric;
    v_costo_total := v_costo_total + v_costo;

    v_mov := jsonb_build_object(
      'id', 'mv-' || v_id || '-' || v_n,
      'ventaId', v_id,
      'productoId', v_item ->> 'productoId',
      'tipo', 'venta',
      'cantidad', -v_cant,
      'motivo', 'Venta ' || v_id,
      'operador', p_venta ->> 'operador',
      'fecha', v_fecha);
    v_movimientos := v_movimientos || v_mov;
  end loop;

  -- ---- fiado ----------------------------------------------------------------
  if v_monto_fiado > 0 then
    select value into v_clientes from app_data where key = 'clientes' for update;
    select (t.ord - 1)::int into v_cidx
    from jsonb_array_elements(coalesce(v_clientes, '[]'::jsonb)) with ordinality as t(elem, ord)
    where t.elem ->> 'id' = v_cliente_id limit 1;
    if v_cidx is null then
      if not p_offline then
        raise exception using errcode = 'P0001', message = 'cliente_no_existe';
      end if;
      v_revision := v_revision || jsonb_build_object('clienteId', v_cliente_id, 'motivo', 'cliente_no_existe');
    else
      v_clientes := jsonb_set(v_clientes, array[v_cidx::text, 'saldo'],
        to_jsonb(coalesce((v_clientes -> v_cidx ->> 'saldo')::numeric, 0) + v_monto_fiado));
      update app_data set value = v_clientes, updated_at = now() where key = 'clientes';
    end if;
  end if;

  -- ---- registrar --------------------------------------------------------------
  v_venta := jsonb_build_object(
    'id', v_id,
    'tipo', 'venta',
    'fecha', v_fecha,
    'items', v_items_final,
    'total', v_total,
    'costoTotal', v_costo_total,
    'utilidad', v_total - v_costo_total,
    'cliente', coalesce(p_venta ->> 'cliente', ''),
    'clienteId', v_cliente_id,
    'operador', p_venta ->> 'operador',
    'pagos', v_pagos,
    'metodoResumen', p_venta ->> 'metodoResumen',
    'registradaPor', public.fn_usuario_actual());
  if p_offline then
    v_venta := v_venta || jsonb_build_object('sinConexion', true);
  end if;
  if jsonb_array_length(v_revision) > 0 then
    v_venta := v_venta || jsonb_build_object('revision', v_revision);
  end if;

  insert into ventas_registro (id, data, creado_en)
  values (v_id, v_venta, to_timestamp(v_fecha / 1000.0));
  insert into movimientos_registro (id, data, creado_en)
  select m ->> 'id', m, to_timestamp(v_fecha / 1000.0) from jsonb_array_elements(v_movimientos) m;

  update app_data set value = v_productos, updated_at = now() where key = 'productos';
  if v_lotes_cambiaron then
    update app_data set value = v_lotes, updated_at = now() where key = 'lotes';
  end if;

  return jsonb_build_object('ok', true, 'venta', v_venta, 'movimientos', v_movimientos,
    'productos', v_productos,
    'lotes', case when v_rol = 'admin' then v_lotes end,
    'clientes', case when v_rol = 'admin' and v_monto_fiado > 0 then v_clientes end);
exception
  when sqlstate 'P0001' then
    if sqlerrm = 'cliente_no_existe' then
      return jsonb_build_object('ok', false, 'motivo', 'cliente_no_existe', 'mensaje', 'El cliente del fiado ya no existe.');
    end if;
    raise;
end;
$$;
revoke execute on function public.registrar_venta(jsonb, boolean) from public, anon;
grant  execute on function public.registrar_venta(jsonb, boolean) to authenticated;
