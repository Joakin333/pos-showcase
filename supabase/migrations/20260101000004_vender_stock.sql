-- ============================================================================
-- 004 · vender_stock: descuento de stock atómico
-- ============================================================================
-- El catálogo vive como un solo arreglo JSON (app_data, key='productos'). Si
-- dos cajas venden a la vez y cada una resta el stock en su propia copia, una
-- puede pisar a la otra y vender una unidad que ya no existe.
--
-- Esta función descuenta en el servidor con SELECT … FOR UPDATE: Postgres
-- bloquea la fila y pone en fila las ventas simultáneas; la segunda espera y
-- ve el stock ya descontado. Revisa todo el carrito antes de tocar nada
-- (todo o nada) y devuelve el catálogo actualizado.
--
-- Ojo: la atomicidad del servidor no alcanza si el cliente, ante un timeout,
-- vuelve a descontar por otro camino. Ese problema está documentado en el
-- README ("Problemas abiertos").
-- ============================================================================

create or replace function vender_stock(items jsonb)
returns jsonb
language plpgsql
as $$
declare
  v_productos jsonb;
  v_item jsonb;
  v_idx int;
  v_stock numeric;
  v_faltantes jsonb := '[]'::jsonb;
begin
  -- Rate limiting: se chequea ANTES de pedir el "for update" de más abajo, para no
  -- generar contención sobre la fila de productos si de entrada se va a rechazar.
  -- fn_verificar_limite viene de la migración 003.
  -- 40 llamadas por minuto por IP: una caja real que confirma una venta a la vez no
  -- se acerca a ese número ni en un día muy bueno; una cola de "vender_stock" en bucle
  -- (script/abuso) sí lo toca en segundos. Si varias cajas del mismo local comparten
  -- una sola IP pública (mismo router/WiFi), comparten también este límite: si eso
  -- pasa y se siente corto, se sube el segundo número (40) sin tocar nada más.
  if not fn_verificar_limite('vender_stock', 40, 60) then
    return jsonb_build_object('ok', false, 'motivo', 'limite_excedido');
  end if;

  -- clave del asunto: bloquea la fila hasta que esta función termine.
  -- una segunda llamada concurrente a esta misma función se queda esperando aquí,
  -- en vez de leer el stock viejo al mismo tiempo que la primera.
  select value into v_productos from app_data where key = 'productos' for update;

  if v_productos is null then
    return jsonb_build_object('ok', false, 'motivo', 'sin_catalogo');
  end if;

  -- primera pasada: solo revisar, no modificar nada todavía
  for v_item in select * from jsonb_array_elements(items)
  loop
    select (ord - 1) into v_idx
    from jsonb_array_elements(v_productos) with ordinality as t(elem, ord)
    where elem->>'id' = (v_item->>'productoId')
    limit 1;

    if v_idx is null then
      v_faltantes := v_faltantes || jsonb_build_object('productoId', v_item->>'productoId', 'motivo', 'no_existe');
      continue;
    end if;

    v_stock := coalesce((v_productos->v_idx->>'stock')::numeric, 0);
    if v_stock < (v_item->>'cantidad')::numeric then
      v_faltantes := v_faltantes || jsonb_build_object('productoId', v_item->>'productoId', 'motivo', 'stock_insuficiente', 'stockActual', v_stock);
    end if;
  end loop;

  if jsonb_array_length(v_faltantes) > 0 then
    -- no se descontó nada: es todo o nada
    return jsonb_build_object('ok', false, 'faltantes', v_faltantes);
  end if;

  -- segunda pasada: ya se confirmó que alcanza para todo, ahora sí se descuenta
  for v_item in select * from jsonb_array_elements(items)
  loop
    select (ord - 1) into v_idx
    from jsonb_array_elements(v_productos) with ordinality as t(elem, ord)
    where elem->>'id' = (v_item->>'productoId')
    limit 1;

    v_stock := coalesce((v_productos->v_idx->>'stock')::numeric, 0);
    v_productos := jsonb_set(v_productos, array[v_idx::text, 'stock'], to_jsonb(v_stock - (v_item->>'cantidad')::numeric));
  end loop;

  update app_data
    set value = v_productos, updated_at = now()
    where key = 'productos';

  return jsonb_build_object('ok', true, 'productos', v_productos);
end;
$$;

-- Permiso inicial; la migración 009 lo restringe a usuarios con sesión.
grant execute on function vender_stock(jsonb) to anon, authenticated;

-- ============================================================================
-- Verificación rápida después de ejecutar esto:
--   select vender_stock('[{"productoId":"ID_DE_UN_PRODUCTO_REAL","cantidad":1}]'::jsonb);
--   Debería devolver {"ok": true, "productos": [...]} y el stock de ese producto
--   bajar en 1 en la tabla app_data (columna value, key='productos').
--
-- Para probar el límite: llamar lo anterior 41 veces seguidas en menos de un
-- minuto (mismo SQL Editor = misma IP para Supabase). Las primeras 40 deberían
-- comportarse normal; de la 41 en adelante debería devolver
-- {"ok": false, "motivo": "limite_excedido"} sin tocar el stock. Ojo: cada
-- llamada exitosa SÍ descuenta stock real, así que conviene probar con una
-- cantidad chica o un producto de prueba.
-- ============================================================================
