-- ============================================================================
-- Login: bloqueo progresivo, límites por clave y por IP
-- ============================================================================
-- La clave de prueba usa 1.000 iteraciones de PBKDF2 (en producción son 100.000)
-- para que la prueba sea rápida; la lógica de bloqueo es la misma.
begin;
create extension if not exists pgtap with schema extensions;
set search_path = public, extensions;
select plan(14);

insert into credenciales (usuario_id, clave)
values ('tlogin', jsonb_build_object('algo', 'pbkdf2', 'sal', repeat('ab', 16), 'iter', 1000,
         'valor', encode(public.pbkdf2_hmac_sha256('correcta', repeat('ab', 16), 1000), 'hex')))
on conflict (usuario_id) do update set clave = excluded.clave;
delete from intentos_credencial where usuario_id = 'tlogin';

create temp table r (k text primary key, v jsonb);
grant all on r to anon, authenticated;

create function pg_temp.fallar() returns jsonb language sql as $$
  select verificar_credencial('tlogin', 'clave', 'incorrecta') $$;
create function pg_temp.vencer() returns void language sql as $$
  update intentos_credencial set bloqueado_hasta = now() - interval '1 second' where usuario_id = 'tlogin' $$;
create function pg_temp.ronda() returns jsonb language plpgsql as $$
declare v jsonb;
begin
  perform pg_temp.vencer();
  for i in 1..5 loop v := pg_temp.fallar(); end loop;
  return v;
end $$;

do $$
declare v jsonb;
begin
  for i in 1..4 loop v := pg_temp.fallar(); end loop;
  insert into r values ('cuatro_fallos', v);
  insert into r values ('bloqueo_1', pg_temp.fallar());
  insert into r values ('correcta_bloqueada', verificar_credencial('tlogin', 'clave', 'correcta'));
  insert into r values ('bloqueo_2', pg_temp.ronda());
  insert into r values ('bloqueo_3', pg_temp.ronda());
  insert into r values ('bloqueo_4', pg_temp.ronda());
  insert into r values ('bloqueo_5', pg_temp.ronda());
  perform pg_temp.vencer();
  insert into r values ('correcta_tras_vencer', verificar_credencial('tlogin', 'clave', 'correcta'));
  insert into r values ('filas_tras_exito', to_jsonb((select count(*) from intentos_credencial where usuario_id = 'tlogin')));
  -- un día sin fallos borra los bloqueos acumulados
  insert into intentos_credencial (usuario_id, intentos, bloqueos, ultimo_fallo)
  values ('tlogin', 0, 3, now() - interval '2 days');
  insert into r values ('tras_un_dia', pg_temp.fallar());
end $$;

select is((select v ->> 'intentosRestantes' from r where k = 'cuatro_fallos'), '1', 'tras 4 fallos queda 1 intento');
select is((select v ->> 'segundos' from r where k = 'bloqueo_1'), '60', '1.er bloqueo: 1 minuto');
select is((select v ->> 'ok' from r where k = 'correcta_bloqueada'), 'false', 'la clave correcta no entra mientras la cuenta está bloqueada');
select is((select v ->> 'segundos' from r where k = 'bloqueo_2'), '300', '2.º bloqueo: 5 minutos');
select is((select v ->> 'segundos' from r where k = 'bloqueo_3'), '900', '3.er bloqueo: 15 minutos');
select is((select v ->> 'segundos' from r where k = 'bloqueo_4'), '1800', '4.º bloqueo: 30 minutos');
select is((select v ->> 'segundos' from r where k = 'bloqueo_5'), '1800', 'el bloqueo no pasa de 30 minutos');
select is((select v ->> 'ok' from r where k = 'correcta_tras_vencer'), 'true', 'vencido el bloqueo, la clave correcta entra');
select is((select (v #>> '{}')::int from r where k = 'filas_tras_exito'), 0, 'un acceso correcto borra el historial de fallos');
select is((select v ->> 'intentosRestantes' from r where k = 'tras_un_dia'), '4', 'tras un día sin fallos se olvidan los bloqueos');

-- ---- límite por clave explícita (lo usa la Edge Function con la IP real) ------------
select is((select string_agg(fn_limite_clave('t-limite', 3, 60)::text, ',') from generate_series(1, 4)),
  'true,true,true,false', 'fn_limite_clave deja pasar 3 y corta el 4.º');

set local role authenticated;
do $$
begin
  begin
    perform fn_limite_clave('x', 1, 1);
    insert into r values ('limite_authenticated', to_jsonb('permitido'::text));
  exception when insufficient_privilege then
    insert into r values ('limite_authenticated', to_jsonb('denegado'::text));
  end;
end $$;
reset role;
select is((select v #>> '{}' from r where k = 'limite_authenticated'), 'denegado',
  'solo el servidor puede usar fn_limite_clave (no una sesión de usuario)');

-- ---- códigos de recuperación: 3 cada 15 minutos por cuenta --------------------------
insert into contactos_recuperacion (usuario_id, email) values ('tlogin', 'a@b.cl')
on conflict (usuario_id) do update set email = excluded.email;
set local role anon;
do $$
declare t text := '';
begin
  for i in 1..4 loop
    t := t || coalesce(rpc_generar_codigo_recuperacion('tlogin', 'email') ->> 'motivo', 'ok') || ',';
  end loop;
  insert into r values ('codigos', to_jsonb(t));
end $$;
reset role;
select is((select v #>> '{}' from r where k = 'codigos'), 'ok,ok,ok,limite_excedido,',
  'pedir códigos: 3 por cuenta y el 4.º se rechaza');

-- ---- IP del llamador -----------------------------------------------------------------
set local request.headers = '{"cf-connecting-ip":"1.2.3.4","x-forwarded-for":"9.9.9.9, 5.6.7.8"}';
select is(fn_identificador_llamador(), '1.2.3.4', 'se usa la IP que fija la infraestructura, no la que escribe el cliente');

select * from finish();
rollback;
