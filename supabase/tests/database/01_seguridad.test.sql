-- ============================================================================
-- Seguridad: qué puede hacer cada rol (anónimo, vendedora, administradora)
-- ============================================================================
-- Cada prueba ejecuta las llamadas con el rol y el JWT de una persona, guarda
-- el resultado en una tabla temporal y lo verifica después como postgres.
-- Todo corre dentro de una transacción que se deshace al final.
begin;
create extension if not exists pgtap with schema extensions;
set search_path = public, extensions;
select plan(16);

-- ---- datos de prueba ----------------------------------------------------------
insert into app_data (key, value) values
  ('usuarios',  '[{"id":"tadmin","nombre":"Admin","rol":"admin","activo":true},
                  {"id":"tvend","nombre":"Vendedora","rol":"vendedor","activo":true},
                  {"id":"tinactiva","nombre":"Ex","rol":"admin","activo":false}]'),
  ('productos', '[{"id":"p1","nombre":"Arroz","precio":1000,"stock":10}]'),
  ('clientes',  '[{"id":"c1","nombre":"Cliente","saldo":0}]')
on conflict (key) do update set value = excluded.value;

create temp table r (k text primary key, v text);
grant all on r to anon, authenticated;

-- ---- anónimo (solo la llave publicable) -------------------------------------
set local role anon;
set local request.jwt.claims = '{"role":"anon"}';
do $$
declare n int;
begin
  insert into r values ('anon_lee', (select string_agg(key, ',' order by key) from app_data));
  begin
    update app_data set value = '[]' where key = 'productos';
    get diagnostics n = row_count;
    insert into r values ('anon_update', n::text || ' filas');
  exception when insufficient_privilege then
    insert into r values ('anon_update', 'denegado');
  end;
  begin
    perform guardar_credencial('tadmin', 'clave', '{"algo":"plano","valor":"x"}');
    insert into r values ('anon_guardar_credencial', 'permitido');
  exception when insufficient_privilege then
    insert into r values ('anon_guardar_credencial', 'denegado');
  end;
  begin
    perform registrar_venta('{}'::jsonb, false);
    insert into r values ('anon_registrar_venta', 'permitido');
  exception when insufficient_privilege then
    insert into r values ('anon_registrar_venta', 'denegado');
  end;
  begin
    insert into ventas_registro (id, data) values ('falsa', '{}');
    insert into r values ('anon_venta_falsa', 'permitido');
  exception when insufficient_privilege then
    insert into r values ('anon_venta_falsa', 'denegado');
  end;
end $$;
reset role;

select is((select v from r where k = 'anon_lee'), 'usuarios',
  'anónimo: solo puede leer la lista de usuarios (para la pantalla de login)');
select is((select v from r where k = 'anon_update'), 'denegado',
  'anónimo: no puede modificar app_data');
select is((select v from r where k = 'anon_guardar_credencial'), 'denegado',
  'anónimo: no puede cambiar la clave de nadie');
select is((select v from r where k = 'anon_registrar_venta'), 'denegado',
  'anónimo: no puede registrar ventas');
select is((select v from r where k = 'anon_venta_falsa'), 'denegado',
  'anónimo: no puede insertar ventas en el historial');

-- ---- vendedora ---------------------------------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"role":"authenticated","app_metadata":{"usuario_id":"tvend"}}';
do $$
declare n int; b jsonb := jsonb_build_object('algo','pbkdf2','sal',repeat('0',32),'iter',100000,'valor',repeat('a',64));
begin
  insert into r values ('vend_rol', fn_rol_actual());
  update app_data set value = value where key = 'productos';
  get diagnostics n = row_count;
  insert into r values ('vend_update_productos', n::text);
  begin
    update app_data
       set value = (select jsonb_agg(case when u->>'id' = 'tvend' then u || '{"rol":"admin"}' else u end)
                    from jsonb_array_elements(value) u)
     where key = 'usuarios';
    insert into r values ('vend_se_sube_a_admin', 'permitido');
  exception when insufficient_privilege then
    insert into r values ('vend_se_sube_a_admin', 'denegado');
  end;
  insert into r values ('vend_clave_ajena', guardar_credencial('tadmin', 'clave', b) ->> 'ok');
  insert into r values ('vend_codigo_maestro', guardar_credencial('__maestro__', 'clave', b) ->> 'ok');
  insert into r values ('vend_clave_plana', guardar_credencial('tvend', 'clave', '{"algo":"plano","valor":"x"}') ->> 'ok');
  insert into r values ('vend_clave_propia', guardar_credencial('tvend', 'clave', b) ->> 'ok');
  insert into r values ('vend_contacto_ajeno', rpc_registrar_contacto_recuperacion('tadmin', 'email', 'otra@persona.cl') ->> 'ok');
end $$;
reset role;

select is((select v from r where k = 'vend_rol'), 'vendedor',
  'vendedora: la base reconoce su rol a partir del JWT');
select is((select v from r where k = 'vend_update_productos'), '0',
  'vendedora: no puede escribir el catálogo directamente (un solo escritor)');
select is((select v from r where k = 'vend_se_sube_a_admin'), 'denegado',
  'vendedora: no puede cambiarse el rol a admin');
select is((select v from r where k = 'vend_clave_ajena'), 'false',
  'vendedora: no puede cambiar la clave de otra persona');
select is((select v from r where k = 'vend_codigo_maestro'), 'false',
  'vendedora: no puede cambiar el código maestro');
select is((select v from r where k = 'vend_clave_plana'), 'false',
  'nadie puede guardar una clave sin PBKDF2');
select is((select v from r where k = 'vend_clave_propia'), 'true',
  'vendedora: sí puede cambiar su propia clave');
select is((select v from r where k = 'vend_contacto_ajeno'), 'false',
  'vendedora: no puede redirigir el código de recuperación de otra persona');

-- ---- administradora y cuentas inválidas -------------------------------------
set local role authenticated;
set local request.jwt.claims = '{"role":"authenticated","app_metadata":{"usuario_id":"tadmin"}}';
do $$
declare n int;
begin
  update app_data set value = value where key = 'clientes';
  get diagnostics n = row_count;
  insert into r values ('admin_update_clientes', n::text);
end $$;
set local request.jwt.claims = '{"role":"authenticated","app_metadata":{"usuario_id":"tinactiva"}}';
do $$ begin insert into r values ('inactiva_lee', (select string_agg(key, ',' order by key) from app_data)); end $$;
-- user_metadata lo puede escribir el propio usuario: no debe dar acceso
set local request.jwt.claims = '{"role":"authenticated","user_metadata":{"usuario_id":"tadmin"}}';
do $$ begin insert into r values ('sin_app_metadata_rol', coalesce(fn_rol_actual(), 'ninguno')); end $$;
reset role;

select is((select v from r where k = 'admin_update_clientes'), '1',
  'administradora: puede escribir clientes');
select is((select v from r where k = 'inactiva_lee'), 'usuarios',
  'una persona desactivada pierde el acceso en el acto');
select is((select v from r where k = 'sin_app_metadata_rol'), 'ninguno',
  'un usuario_id en user_metadata (editable por el usuario) no otorga rol');

select * from finish();
rollback;
