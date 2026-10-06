-- ============================================================================
-- Mínimo privilegio: qué ve y qué escribe cada rol, y qué expone la API
-- ============================================================================
begin;
create extension if not exists pgtap with schema extensions;
set search_path = public, extensions;
select plan(17);

alter table ventas_registro disable trigger trg_notificar_venta_nueva;

insert into app_data (key, value) values
  ('usuarios',  '[{"id":"tadmin","nombre":"Admin","rol":"admin","activo":true,"pregunta":"original"},
                  {"id":"tvend","nombre":"Vendedora","rol":"vendedor","activo":true,"pregunta":""}]'),
  ('productos', '[{"id":"p1","nombre":"Arroz","precio":1000,"stock":10}]'),
  ('lotes',     '[{"id":"l1","productoId":"p1","cantidadRestante":10,"costoUnitario":300,"fecha":1}]'),
  ('clientes',  '[{"id":"c1","nombre":"Cliente","saldo":5000}]'),
  ('turnos',    jsonb_build_array(jsonb_build_object('id','t1','estado','abierto',
                  'fechaApertura', (extract(epoch from now() - interval '1 hour') * 1000)::bigint)))
on conflict (key) do update set value = excluded.value;

insert into ventas_registro (id, data, creado_en) values
  ('vieja-0001', '{"id":"vieja-0001","total":1,"utilidad":1}', now() - interval '2 days'),
  ('nueva-0001', '{"id":"nueva-0001","total":1,"utilidad":1}', now());
insert into movimientos_registro (id, data) values ('mov-0001', '{"id":"mov-0001"}');

create temp table r (k text primary key, v text);
grant all on r to authenticated;

create function pg_temp.intentar(p_sql text) returns text language plpgsql as $$
begin execute p_sql; return 'permitido';
exception when insufficient_privilege then return 'denegado';
          when others then return 'error ' || sqlstate; end $$;
create function pg_temp.filas(p_sql text) returns text language plpgsql as $$
declare n int;
begin execute p_sql; get diagnostics n = row_count; return n::text;
exception when insufficient_privilege then return 'denegado';
          when others then return 'error ' || sqlstate; end $$;

-- ---- vendedora, con un turno abierto ---------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"role":"authenticated","app_metadata":{"usuario_id":"tvend"}}';
do $$
declare lotes_v jsonb;
begin
  insert into r values ('v_claves', (select string_agg(key, ',' order by key) from app_data));
  insert into r values ('v_ventas', (select count(*)::text from ventas_registro));
  insert into r values ('v_movs',   (select count(*)::text from movimientos_registro));
  insert into r values ('v_ins_venta', pg_temp.intentar($q$insert into ventas_registro (id, data) values ('forjada-01', '{}')$q$));
  insert into r values ('v_ins_mov',   pg_temp.intentar($q$insert into movimientos_registro (id, data) values ('forjado-01', '{}')$q$));
  insert into r values ('v_pregunta_propia', pg_temp.filas($q$update app_data set value = (select jsonb_agg(case when u->>'id'='tvend' then u || '{"pregunta":"mi pregunta"}' else u end) from jsonb_array_elements(value) u) where key='usuarios'$q$));
  insert into r values ('v_pregunta_ajena', pg_temp.intentar($q$update app_data set value = (select jsonb_agg(case when u->>'id'='tadmin' then u || '{"pregunta":"hackeada"}' else u end) from jsonb_array_elements(value) u) where key='usuarios'$q$));
  insert into r values ('v_nombre_propio', pg_temp.intentar($q$update app_data set value = (select jsonb_agg(case when u->>'id'='tvend' then u || '{"nombre":"Otro nombre"}' else u end) from jsonb_array_elements(value) u) where key='usuarios'$q$));
  insert into r values ('v_lotes_en_venta', (registrar_venta('{"id":"venta-0001","pagos":[{"metodo":"efectivo","monto":1000}],"items":[{"productoId":"p1","cantidad":1,"precioUnitario":1000}]}', false) -> 'lotes')::text);
end $$;
reset role;

-- sin turno abierto la vendedora no ve ninguna venta
update app_data set value = jsonb_build_array(jsonb_build_object('id','t1','estado','cerrado','fechaApertura', 1)) where key = 'turnos';
set local role authenticated;
do $$ begin insert into r values ('v_ventas_sin_turno', (select count(*)::text from ventas_registro)); end $$;
reset role;

-- ---- administradora ------------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"role":"authenticated","app_metadata":{"usuario_id":"tadmin"}}';
do $$
begin
  insert into r values ('a_claves', (select string_agg(key, ',' order by key) from app_data));
  insert into r values ('a_ins_venta', pg_temp.intentar($q$insert into ventas_registro (id, data) values ('abono-0001', '{"tipo":"abono"}')$q$));
  insert into r values ('a_ins_mov',   pg_temp.intentar($q$insert into movimientos_registro (id, data) values ('entrada-01', '{}')$q$));
  insert into r values ('a_lotes_en_venta', jsonb_typeof(registrar_venta('{"id":"venta-0002","pagos":[{"metodo":"efectivo","monto":1000}],"items":[{"productoId":"p1","cantidad":1,"precioUnitario":1000}]}', false) -> 'lotes'));
end $$;
reset role;

select is((select v from r where k='v_claves'), 'productos,turnos,usuarios',
  'vendedora: ve el catálogo, los turnos y la lista de personas, y nada más (ni lotes ni clientes)');
select is((select v from r where k='v_ventas'), '1', 'vendedora: ve solo las ventas de su turno abierto');
select is((select v from r where k='v_movs'), '0', 'vendedora: no ve los movimientos de inventario');
select is((select v from r where k='v_ins_venta'), 'denegado', 'vendedora: no puede insertar ventas falsas en el historial');
select is((select v from r where k='v_ins_mov'), 'denegado', 'vendedora: no puede insertar movimientos falsos');
select is((select v from r where k='v_pregunta_propia'), '1', 'vendedora: sí puede cambiar su propia pregunta de seguridad');
select is((select v from r where k='v_pregunta_ajena'), 'denegado', 'vendedora: no puede cambiar la pregunta de la administradora');
select is((select v from r where k='v_nombre_propio'), 'denegado', 'vendedora: no puede cambiarse el nombre ni el rol');
select is((select v from r where k='v_lotes_en_venta'), 'null', 'vendedora: la respuesta de una venta no incluye los lotes (costos)');
select is((select v from r where k='v_ventas_sin_turno'), '0', 'sin turno abierto, la vendedora no ve ventas');
select is((select v from r where k='a_claves'), 'clientes,lotes,productos,turnos,usuarios', 'administradora: ve todo');
select is((select v from r where k='a_ins_venta') || '+' || (select v from r where k='a_ins_mov'), 'permitido+permitido',
  'administradora: puede registrar abonos y movimientos de entrada');
select is((select v from r where k='a_lotes_en_venta'), 'array', 'administradora: la respuesta de una venta sí incluye los lotes');

-- ---- tablas selladas: ningún permiso para anon ni authenticated -------------------
select is((select count(*)::int
           from unnest(array['credenciales','credenciales_usuario','intentos_credencial','intentos_login','limite_llamadas',
                             'respaldos_app_data','push_suscripciones','contactos_recuperacion','recuperacion_codigos']) t,
                unnest(array['anon','authenticated']) rol
           where has_table_privilege(rol, 'public.' || t, 'select,insert,update,delete,truncate,references,trigger')),
  0, 'las 9 tablas selladas no tienen ningún permiso para anon ni authenticated');

-- ---- superficie de la API: lista cerrada de funciones ejecutables -----------------
select is((select string_agg(p.proname, ',' order by p.proname)
           from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'public' and p.prokind = 'f' and has_function_privilege('anon', p.oid, 'execute')),
  'rpc_canales_disponibles,rpc_generar_codigo_recuperacion,rpc_sembrar_inicial,rpc_verificar_codigo_recuperacion,verificar_credencial',
  'anónimo: solo puede ejecutar las 5 funciones de login y recuperación');
select is((select string_agg(p.proname, ',' order by p.proname)
           from pg_proc p join pg_namespace n on n.oid = p.pronamespace
           where n.nspname = 'public' and p.prokind = 'f'
             and has_function_privilege('authenticated', p.oid, 'execute') and not has_function_privilege('anon', p.oid, 'execute')),
  'eliminar_credencial,eliminar_suscripcion_push,fn_es_admin,fn_inicio_turno_abierto,fn_normalizar_usuarios,fn_puede_escribir_clave,fn_rol_actual,fn_usuario_actual,fn_verificar_limite,guardar_credencial,guardar_suscripcion_push,registrar_salida_stock,registrar_venta,rpc_registrar_contacto_recuperacion',
  'con sesión: solo se agregan 14 funciones, todas conocidas (si aparece una nueva, esta prueba falla)');

-- ---- el registro público de cuentas está cerrado en la base -----------------------
select is(pg_temp.intentar($q$insert into auth.users (id, email, raw_app_meta_data) values (gen_random_uuid(), 'intruso@example.com', '{}')$q$),
  'denegado', 'no se puede crear una cuenta de Auth con un correo real (registro público cerrado)');

select * from finish();
rollback;
