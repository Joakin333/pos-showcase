-- ============================================================================
-- 008 · Aviso push a la administradora en cada venta
-- ============================================================================
-- Flujo:
--   1. Desde la PWA instalada, la admin activa "Avisos de venta": el navegador
--      pide permiso, registra /sw.js y guarda la suscripción en
--      push_suscripciones (RPC guardar_suscripcion_push).
--   2. Al insertar una venta en ventas_registro (que no sea un abono), el
--      trigger fn_notificar_venta_nueva llama de forma asíncrona (pg_net) a
--      la Edge Function notificar-venta, sin frenar la venta.
--   3. La Edge Function envía un Web Push firmado con llaves VAPID a cada
--      suscripción; sw.js muestra la notificación.
--
-- Secretos (nunca en archivos versionados):
--   * WEBHOOK_SECRET: se guarda en Supabase Vault (ver más abajo) y como
--     secret de la Edge Function; ambos valores deben coincidir.
--   * VAPID_PRIVATE_KEY: solo como secret de la Edge Function. La llave
--     pública va en index.html (VAPID_PUBLIC_KEY).
--
-- Notas:
--   * En iPhone, Web Push solo funciona con la PWA agregada a la pantalla de
--     inicio y en iOS 16.4 o superior.
--   * Las suscripciones dadas de baja (404/410) las borra la Edge Function.
-- ============================================================================

-- pg_net: Supabase lo instala en el esquema public y no permite reubicarlo
-- (ALTER EXTENSION ... SET SCHEMA falla con "does not support SET SCHEMA");
-- es una limitación conocida de la plataforma, no de esta app.
create extension if not exists pg_net;

create table if not exists push_suscripciones (
  id bigint generated always as identity primary key,
  endpoint text not null unique,
  p256dh text not null,
  auth text not null,
  creado_en timestamptz not null default now()
);
alter table push_suscripciones enable row level security;
-- Sin políticas a propósito: nadie la lee/lista por la API directa. El
-- cliente solo puede insertar/borrar SU PROPIA suscripción vía las RPC de
-- abajo; la Edge Function lee todas con la service role (ignora RLS).

create or replace function guardar_suscripcion_push(p_endpoint text, p_p256dh text, p_auth text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  if not fn_verificar_limite('guardar_suscripcion_push', 10, 60) then
    raise exception 'Demasiados intentos, espera un momento.';
  end if;
  insert into push_suscripciones (endpoint, p256dh, auth)
  values (p_endpoint, p_p256dh, p_auth)
  on conflict (endpoint) do update set p256dh = excluded.p256dh, auth = excluded.auth, creado_en = now();
end;
$$;
grant execute on function guardar_suscripcion_push(text,text,text) to anon, authenticated;

create or replace function eliminar_suscripcion_push(p_endpoint text)
returns void
language plpgsql
security definer
set search_path = public
as $$
begin
  delete from push_suscripciones where endpoint = p_endpoint;
end;
$$;
grant execute on function eliminar_suscripcion_push(text) to anon, authenticated;

-- El secreto compartido con la Edge Function vive en Vault, NO en el código
-- de esta función. Primera vez que se corre este script en un proyecto nuevo:
-- reemplazar el valor de abajo por uno propio antes de ejecutar, y borrar ese
-- valor del archivo antes de hacer commit (o mejor: correr ese INSERT a mano
-- en el SQL Editor, nunca desde un archivo versionado).
--
--   select vault.create_secret(
--     'REEMPLAZAR-POR-UN-VALOR-ALEATORIO-PROPIO-ANTES-DE-CORRER',
--     'webhook_secret_notificar_venta',
--     'Secreto compartido entre fn_notificar_venta_nueva y la Edge Function notificar-venta.'
--   );

create or replace function fn_notificar_venta_nueva()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
declare
  v_secret text;
begin
  if (NEW.data->>'tipo') is distinct from 'abono' then
    select decrypted_secret into v_secret from vault.decrypted_secrets where name = 'webhook_secret_notificar_venta';
    if v_secret is not null then
      perform net.http_post(
        url := 'https://TU-PROYECTO-REF.supabase.co/functions/v1/notificar-venta',
        body := jsonb_build_object('data', NEW.data),
        headers := jsonb_build_object(
          'Content-Type', 'application/json',
          'x-webhook-secret', v_secret
        )
      );
    end if;
  end if;
  return NEW;
end;
$$;

drop trigger if exists trg_notificar_venta_nueva on ventas_registro;
create trigger trg_notificar_venta_nueva
after insert on ventas_registro
for each row execute function fn_notificar_venta_nueva();

-- fn_notificar_venta_nueva es la función de un trigger: Postgres la invoca
-- solo al disparar el trigger, nunca necesita EXECUTE directo de anon/
-- authenticated, así que se le quita el permiso de ejecución desde la API:
revoke execute on function fn_notificar_venta_nueva() from public, anon, authenticated;

-- ============================================================================
-- Verificación rápida:
--   -- ¿hay alguna suscripción guardada?
--   select id, creado_en from push_suscripciones order by id desc;
--   -- ¿el secreto está en Vault?
--   select name, created_at from vault.secrets where name = 'webhook_secret_notificar_venta';
-- ============================================================================
