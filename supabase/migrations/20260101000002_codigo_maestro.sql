-- ============================================================================
-- 002 · Código maestro fuera de app_data
-- ============================================================================
-- El código maestro (para que la administradora recupere el acceso) vivía en
-- texto plano dentro de app_data, que se lee con la llave pública. Ahora se
-- guarda hasheado en la tabla sellada "credenciales", bajo el usuario
-- reservado '__maestro__', y se valida con verificar_credencial (bloqueo de
-- 5 intentos / 60 s). El navegador nunca puede volver a leerlo.
--
-- En una base nueva esta migración no hace nada: el código maestro se define
-- la primera vez desde la app (Ajustes → código maestro).
-- ============================================================================

-- NOTA sobre esta migración en una base NUEVA (dev local): la sección de abajo
-- solo copia un código maestro que ya existiera en app_data.auth_config. En una
-- base recién creada esa fila está vacía, así que el INSERT...SELECT no inserta
-- nada -- es un no-op seguro, no un error. En un clon local, el código maestro
-- se define la primera vez desde la propia app (Ajustes -> código maestro), que
-- llama a guardar_credencial('__maestro__', 'clave', ...).

-- 1) Siembra (desde el código actual en auth_config)
insert into public.credenciales (usuario_id, clave, actualizado_en)
select '__maestro__',
       jsonb_build_object(
         'algo', 'pbkdf2',
         'sal', x.sal,
         'iter', 100000,
         'valor', encode(public.pbkdf2_hmac_sha256(x.codigo, x.sal, 100000), 'hex')
       ),
       now()
from (
  select value->>'codigoMaestro' as codigo,
         encode(extensions.gen_random_bytes(16), 'hex') as sal
  from public.app_data
  where key = 'auth_config' and nullif(value->>'codigoMaestro', '') is not null
) x
on conflict (usuario_id) do nothing;

-- 2) Limpieza (SOLO después de desplegar el index.html nuevo)
-- update public.app_data set value = '{}'::jsonb, updated_at = now() where key = 'auth_config';
