-- ============================================================================
-- 010 · registrar_venta: una venta = una transacción idempotente
-- ============================================================================
-- El problema (README, "Concurrencia de una venta"): el navegador esperaba a
-- vender_stock 3 segundos y, si no llegaba la respuesta, descontaba el stock
-- por un camino de respaldo. Como el servidor pudo haber hecho COMMIT igual, el
-- stock bajaba dos veces. Además, una venta eran varias escrituras sueltas
-- (stock, lotes, fiado, venta, movimientos) y el costo FIFO se calculaba en el
-- navegador, fuera de cualquier bloqueo.
--
-- La solución:
--   1) registrar_venta hace todo en una sola transacción: inserta la venta y
--      sus movimientos, descuenta stock, consume los lotes FIFO (y calcula el
--      costo aquí) y suma el fiado. Todo o nada.
--   2) Es idempotente por el id de la venta (lo genera el dispositivo). Si la
--      misma venta llega dos veces, devuelve lo que ya registró sin aplicarla
--      de nuevo. Ante un timeout, el cliente reintenta la MISMA llamada.
--   3) Una venta hecha sin conexión (p_offline = true) ya ocurrió en el mundo
--      real: se acepta aunque deje el stock negativo, y queda marcada para
--      revisión en vez de esconderse.
--   4) registrar_salida_stock hace lo mismo para las mermas y ajustes de
--      salida, que también consumen lotes.
--   5) La vendedora deja de poder escribir 'productos' y 'lotes' directamente:
--      la única forma de mover stock por una venta es esta función.
--
-- Orden de bloqueo (siempre el mismo, para no provocar deadlocks):
--   productos → lotes → clientes.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- FIFO: consume `p_cantidad` de los lotes de un producto, del más antiguo al
-- más nuevo. Devuelve los lotes actualizados y el costo de lo consumido. Si
-- los lotes no alcanzan, el resto se costea con el último costo conocido o,
-- sin lotes, con el precio de venta (utilidad 0 en esa porción). Es la misma
-- regla que usaba la app en el navegador.
-- ---------------------------------------------------------------------------
create or replace function public._consumir_fifo(p_lotes jsonb, p_producto text, p_cantidad numeric, p_precio_fallback numeric)
returns jsonb
language plpgsql
immutable
set search_path = ''
as $$
declare
  r record;
  v_resto numeric := p_cantidad;
  v_costo numeric := 0;
  v_ultimo numeric := null;
  v_disponible numeric;
  v_tomar numeric;
begin
  for r in
    select (t.ord - 1)::int as idx, t.elem
    from jsonb_array_elements(coalesce(p_lotes, '[]'::jsonb)) with ordinality as t(elem, ord)
    where t.elem ->> 'productoId' = p_producto
      and coalesce((t.elem ->> 'cantidadRestante')::numeric, 0) > 0
    order by coalesce((t.elem ->> 'fecha')::numeric, 0), t.ord
  loop
    exit when v_resto <= 0;
    v_ultimo := coalesce((r.elem ->> 'costoUnitario')::numeric, 0);
    v_disponible := coalesce((r.elem ->> 'cantidadRestante')::numeric, 0);
    v_tomar := least(v_disponible, v_resto);
    p_lotes := jsonb_set(p_lotes, array[r.idx::text, 'cantidadRestante'], to_jsonb(v_disponible - v_tomar));
    v_costo := v_costo + v_tomar * v_ultimo;
    v_resto := v_resto - v_tomar;
  end loop;
  if v_resto > 0 then
    v_costo := v_costo + v_resto * coalesce(v_ultimo, p_precio_fallback, 0);
  end if;
  return jsonb_build_object('lotes', coalesce(p_lotes, '[]'::jsonb), 'costo', v_costo);
end;
$$;
revoke execute on function public._consumir_fifo(jsonb, text, numeric, numeric) from public, anon, authenticated;

-- Número decimal no negativo escrito como texto JSON (para validar sin que un
-- cast inválido aborte la función).
create or replace function public._es_numero(p text)
returns boolean
language sql
immutable
set search_path = ''
as $$
  select coalesce(p ~ '^[0-9]+(\.[0-9]+)?$', false);
$$;
revoke execute on function public._es_numero(text) from public, anon, authenticated;

-- ---------------------------------------------------------------------------
-- registrar_venta
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
    from movimientos_registro where id like 'mv-' || v_id || '-%';
    select value into v_lotes from app_data where key = 'lotes';
    select value into v_clientes from app_data where key = 'clientes';
    return jsonb_build_object('ok', true, 'duplicada', true, 'venta', v_venta,
      'movimientos', v_movimientos, 'productos', v_productos,
      'lotes', coalesce(v_lotes, '[]'::jsonb), 'clientes', coalesce(v_clientes, '[]'::jsonb));
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
    'productos', v_productos, 'lotes', v_lotes,
    'clientes', case when v_monto_fiado > 0 then v_clientes end);
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

-- ---------------------------------------------------------------------------
-- registrar_salida_stock: merma o ajuste de salida (solo administradora)
-- ---------------------------------------------------------------------------
create or replace function public.registrar_salida_stock(p_mov jsonb)
returns jsonb
language plpgsql
security definer
set search_path = public
as $$
declare
  v_id text := p_mov ->> 'id';
  v_producto text := p_mov ->> 'productoId';
  v_cant numeric;
  v_productos jsonb;
  v_lotes jsonb;
  v_idx int;
  v_stock numeric;
  v_fifo jsonb;
  v_mov jsonb;
  v_fecha numeric;
begin
  if not public.fn_es_admin() then
    return jsonb_build_object('ok', false, 'motivo', 'no_permitido', 'mensaje', 'Solo la administradora ajusta stock.');
  end if;
  if v_id is null or v_id !~ '^[A-Za-z0-9_-]{4,64}$' or coalesce(v_producto, '') = ''
     or not public._es_numero(p_mov ->> 'cantidad') or (p_mov ->> 'cantidad')::numeric <= 0
     or coalesce(p_mov ->> 'tipo', '') not in ('salida', 'ajuste') then
    return jsonb_build_object('ok', false, 'motivo', 'datos_invalidos', 'mensaje', 'Ajuste inválido.');
  end if;
  v_cant := (p_mov ->> 'cantidad')::numeric;
  v_fecha := case when public._es_numero(p_mov ->> 'fecha') then (p_mov ->> 'fecha')::numeric
                  else extract(epoch from now()) * 1000 end;

  select value into v_productos from app_data where key = 'productos' for update;

  select data into v_mov from movimientos_registro where id = v_id;
  if found then
    select value into v_lotes from app_data where key = 'lotes';
    return jsonb_build_object('ok', true, 'duplicada', true, 'movimiento', v_mov,
      'productos', v_productos, 'lotes', coalesce(v_lotes, '[]'::jsonb));
  end if;

  select (t.ord - 1)::int into v_idx
  from jsonb_array_elements(coalesce(v_productos, '[]'::jsonb)) with ordinality as t(elem, ord)
  where t.elem ->> 'id' = v_producto limit 1;
  if v_idx is null then
    return jsonb_build_object('ok', false, 'motivo', 'no_existe', 'mensaje', 'El producto ya no existe.');
  end if;
  v_stock := coalesce((v_productos -> v_idx ->> 'stock')::numeric, 0);
  if v_stock < v_cant then
    return jsonb_build_object('ok', false, 'motivo', 'stock_insuficiente', 'stockActual', v_stock,
      'mensaje', 'No hay tanto stock para descontar.');
  end if;

  select value into v_lotes from app_data where key = 'lotes' for update;
  v_fifo := public._consumir_fifo(coalesce(v_lotes, '[]'::jsonb), v_producto, v_cant,
              coalesce((v_productos -> v_idx ->> 'precio')::numeric, 0));
  v_productos := jsonb_set(v_productos, array[v_idx::text, 'stock'], to_jsonb(v_stock - v_cant));

  v_mov := jsonb_build_object(
    'id', v_id, 'productoId', v_producto, 'tipo', p_mov ->> 'tipo',
    'cantidad', -v_cant, 'motivo', coalesce(p_mov ->> 'motivo', ''),
    'operador', p_mov ->> 'operador', 'fecha', v_fecha,
    'costoTotal', (v_fifo ->> 'costo')::numeric);

  insert into movimientos_registro (id, data, creado_en) values (v_id, v_mov, to_timestamp(v_fecha / 1000.0));
  update app_data set value = v_productos, updated_at = now() where key = 'productos';
  update app_data set value = v_fifo -> 'lotes', updated_at = now() where key = 'lotes';

  return jsonb_build_object('ok', true, 'movimiento', v_mov, 'productos', v_productos, 'lotes', v_fifo -> 'lotes');
end;
$$;
revoke execute on function public.registrar_salida_stock(jsonb) from public, anon;
grant  execute on function public.registrar_salida_stock(jsonb) to authenticated;

-- ---------------------------------------------------------------------------
-- Un solo escritor: la vendedora ya no escribe 'productos' ni 'lotes'.
-- Su stock solo cambia a través de registrar_venta.
-- ---------------------------------------------------------------------------
create or replace function public.fn_puede_escribir_clave(p_key text)
returns boolean
language sql
stable
set search_path = public
as $$
  select case public.fn_rol_actual()
    when 'admin' then true
    when 'vendedor' then p_key in ('turnos', 'retiros', 'usuarios')
    else false
  end;
$$;

-- La función anterior queda fuera de la API: la app ya no la usa, y dejarla
-- abierta permitiría volver al camino viejo.
revoke execute on function public.vender_stock(jsonb) from public, anon, authenticated;
