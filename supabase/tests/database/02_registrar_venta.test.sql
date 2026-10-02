-- ============================================================================
-- registrar_venta / registrar_salida_stock: transacción, idempotencia y FIFO
-- ============================================================================
-- Datos: el producto p1 tiene stock 10 y dos lotes, el más antiguo con 3
-- unidades a $100 y el siguiente con 10 a $200. El producto p2 tiene stock 5 y
-- un lote de 5 a $50. Todo se deshace al final (rollback).
begin;
create extension if not exists pgtap with schema extensions;
set search_path = public, extensions;
select plan(24);

alter table ventas_registro disable trigger trg_notificar_venta_nueva;

insert into app_data (key, value) values
  ('usuarios',  '[{"id":"tadmin","nombre":"Admin","rol":"admin","activo":true},
                  {"id":"tvend","nombre":"Vendedora","rol":"vendedor","activo":true}]'),
  ('productos', '[{"id":"p1","nombre":"Arroz","precio":1000,"stock":10},
                  {"id":"p2","nombre":"Aceite","precio":500,"stock":5}]'),
  ('lotes',     '[{"id":"l1","productoId":"p1","cantidadRestante":3,"costoUnitario":100,"fecha":1},
                  {"id":"l2","productoId":"p1","cantidadRestante":10,"costoUnitario":200,"fecha":2},
                  {"id":"l3","productoId":"p2","cantidadRestante":5,"costoUnitario":50,"fecha":1}]'),
  ('clientes',  '[{"id":"c1","nombre":"Cliente","saldo":0}]')
on conflict (key) do update set value = excluded.value;

create temp table r (k text primary key, v jsonb);
grant all on r to authenticated;

create function pg_temp.stock(p text) returns numeric language sql as $$
  select (e ->> 'stock')::numeric from app_data, jsonb_array_elements(value) e
  where key = 'productos' and e ->> 'id' = p $$;
create function pg_temp.lote(p text) returns numeric language sql as $$
  select (e ->> 'cantidadRestante')::numeric from app_data, jsonb_array_elements(value) e
  where key = 'lotes' and e ->> 'id' = p $$;
-- Llama a la función y, si lanza un error, lo devuelve como {"error": ...} en vez
-- de abortar el archivo: así cada falla aparece como una aserción concreta.
create function pg_temp.vender(p_venta jsonb, p_offline boolean) returns jsonb language plpgsql as $$
begin
  return registrar_venta(p_venta, p_offline);
exception when others then
  return jsonb_build_object('error', sqlerrm);
end $$;
create function pg_temp.salida(p_mov jsonb) returns jsonb language plpgsql as $$
begin
  return registrar_salida_stock(p_mov);
exception when others then
  return jsonb_build_object('error', sqlerrm);
end $$;
create function pg_temp.venta(p_id text, p_prod text, p_cant numeric, p_metodo text default 'efectivo')
returns jsonb language sql as $$
  select jsonb_build_object('id', p_id, 'operador', 'Prueba', 'fecha', 1790900000000,
    'pagos', jsonb_build_array(jsonb_build_object('metodo', p_metodo, 'monto', p_cant * 1000)),
    'items', jsonb_build_array(jsonb_build_object('productoId', p_prod, 'nombre', 'x',
                                                  'cantidad', p_cant, 'precioUnitario', 1000))) $$;

-- ---- como vendedora ----------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"role":"authenticated","app_metadata":{"usuario_id":"tvend"}}';
do $$
begin
  insert into r values ('normal',      pg_temp.vender(pg_temp.venta('venta-0001', 'p1', 2), false));
  insert into r values ('stock_1',     to_jsonb(pg_temp.stock('p1')));
  insert into r values ('repetida',    pg_temp.vender(pg_temp.venta('venta-0001', 'p1', 2), false));
  insert into r values ('stock_2',     to_jsonb(pg_temp.stock('p1')));
  insert into r values ('agrupada',    pg_temp.vender(
    '{"id":"venta-0002","pagos":[{"metodo":"efectivo","monto":4000}],
      "items":[{"productoId":"p1","cantidad":2,"precioUnitario":1000},
               {"productoId":"p1","cantidad":2,"precioUnitario":1000}]}', false));
  insert into r values ('stock_3',     to_jsonb(pg_temp.stock('p1')));
  insert into r values ('negativa',    pg_temp.vender(pg_temp.venta('venta-0003', 'p1', -5), false));
  insert into r values ('sin_stock',   pg_temp.vender(pg_temp.venta('venta-0004', 'p1', 50), false));
  insert into r values ('stock_4',     to_jsonb(pg_temp.stock('p1')));
  insert into r values ('offline',     pg_temp.vender(pg_temp.venta('venta-0005', 'p1', 50), true));
  insert into r values ('stock_5',     to_jsonb(pg_temp.stock('p1')));
  insert into r values ('vend_fiado',  pg_temp.vender(pg_temp.venta('venta-0006', 'p2', 1, 'fiado') || '{"clienteId":"c1"}', false));
  insert into r values ('vend_merma',  pg_temp.salida('{"id":"merma-0001","productoId":"p2","cantidad":1,"tipo":"salida"}'));
end $$;

-- ---- como administradora -----------------------------------------------------
set local request.jwt.claims = '{"role":"authenticated","app_metadata":{"usuario_id":"tadmin"}}';
do $$
begin
  insert into r values ('fiado',       pg_temp.vender(pg_temp.venta('venta-0007', 'p2', 1, 'fiado') || '{"clienteId":"c1"}', false));
  insert into r values ('fiado_malo',  pg_temp.vender(pg_temp.venta('venta-0008', 'p2', 1, 'fiado') || '{"clienteId":"no-existe"}', false));
  insert into r values ('merma',       pg_temp.salida('{"id":"merma-0002","productoId":"p2","cantidad":2,"tipo":"salida"}'));
  insert into r values ('merma_rep',   pg_temp.salida('{"id":"merma-0002","productoId":"p2","cantidad":2,"tipo":"salida"}'));
end $$;
reset role;

-- ---- venta normal e idempotencia ----------------------------------------------
select is((select v ->> 'ok' from r where k = 'normal'), 'true', 'una venta normal se registra');
select is((select v from r where k = 'stock_1'), '8'::jsonb, 'y descuenta el stock: 10 → 8');
select is((select (v -> 'venta' ->> 'costoTotal')::numeric from r where k = 'normal'), 200::numeric,
  'el costo sale del lote más antiguo: 2 × $100');
select is((select v ->> 'duplicada' from r where k = 'repetida'), 'true',
  'la misma venta enviada otra vez se reconoce como duplicada');
select is((select v from r where k = 'stock_2'), '8'::jsonb,
  'y NO descuenta el stock una segunda vez');

-- ---- validación y FIFO entre lotes ------------------------------------------
select is((select jsonb_array_length(v -> 'venta' -> 'items') from r where k = 'agrupada'), 1,
  'dos líneas del mismo producto se agrupan en una');
select is((select v from r where k = 'stock_3'), '4'::jsonb, 'las líneas agrupadas descuentan 2 + 2');
select is((select (v -> 'venta' ->> 'costoTotal')::numeric from r where k = 'agrupada'), 700::numeric,
  'FIFO entre dos lotes: 1 × $100 + 3 × $200');
select is((select v ->> 'motivo' from r where k = 'negativa'), 'datos_invalidos',
  'una cantidad negativa se rechaza');
select is((select v ->> 'motivo' from r where k = 'sin_stock'), 'stock_insuficiente',
  'en línea, una venta sin stock suficiente se rechaza');
select is((select v from r where k = 'stock_4'), '4'::jsonb, 'y no toca el stock');

-- ---- venta hecha sin conexión ------------------------------------------------
select is((select v ->> 'ok' from r where k = 'offline'), 'true',
  'una venta hecha sin conexión se acepta aunque no alcance el stock');
select is((select v from r where k = 'stock_5'), '-46'::jsonb,
  'y deja el stock negativo a la vista (no lo esconde en 0)');
select is((select v -> 'venta' -> 'revision' -> 0 ->> 'motivo' from r where k = 'offline'), 'stock_insuficiente',
  'y queda marcada para revisión');

-- ---- historial ------------------------------------------------------------------
select is((select count(*)::int from ventas_registro where id like 'venta-%'), 4,
  'el historial tiene exactamente 4 ventas (la repetida no se duplicó)');
select is((select count(*)::int from movimientos_registro where id like 'mv-venta-0001-%'), 1,
  'la venta repetida tiene un solo movimiento');
select is(pg_temp.lote('l1'), 0::numeric, 'el lote más antiguo quedó vacío');

-- ---- permisos por rol ------------------------------------------------------------
select is((select v ->> 'motivo' from r where k = 'vend_fiado'), 'no_permitido',
  'la vendedora no puede vender al fiado');
select is((select v ->> 'motivo' from r where k = 'vend_merma'), 'no_permitido',
  'la vendedora no puede registrar mermas');

-- ---- fiado ----------------------------------------------------------------------
select is((select (e ->> 'saldo')::numeric from app_data, jsonb_array_elements(value) e
           where key = 'clientes' and e ->> 'id' = 'c1'), 1000::numeric,
  'un fiado suma el monto al saldo del cliente');
select is((select v ->> 'motivo' from r where k = 'fiado_malo'), 'cliente_no_existe',
  'un fiado a un cliente inexistente se rechaza');
select is(pg_temp.stock('p2') + 0, 2::numeric,
  'y se deshace por completo: el stock de p2 solo bajó por el fiado válido y la merma (5 − 1 − 2)');

-- ---- mermas -----------------------------------------------------------------------
select is((select (v -> 'movimiento' ->> 'costoTotal')::numeric from r where k = 'merma'), 100::numeric,
  'una merma consume lotes FIFO: 2 × $50');
select is((select v ->> 'duplicada' from r where k = 'merma_rep'), 'true',
  'la misma merma enviada otra vez no se aplica dos veces');

select * from finish();
rollback;
