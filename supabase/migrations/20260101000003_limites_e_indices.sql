-- ============================================================================
-- 003 · Límite de llamadas (rate limiting) e índices de historial
-- ============================================================================
--   1) limite_llamadas: registro mínimo de "qué acción, desde qué IP, cuándo".
--   2) fn_verificar_limite(): cualquier RPC la llama al inicio para saber si
--      debe seguir. Devuelve boolean en vez de lanzar una excepción, para que
--      cada RPC responda {ok:false, motivo:'limite_excedido'} y el cliente lo
--      distinga de un error de red.
--   3) Índices en creado_en de ventas_registro y movimientos_registro, para
--      que cargar el historial reciente no recorra la tabla completa.
--   4) Limpieza periódica de limite_llamadas.
--
-- Limitación conocida: la IP se toma del primer valor de X-Forwarded-For,
-- que el cliente puede falsificar. Sirve como freno, no como barrera.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1) Tabla de registro de llamadas
-- ---------------------------------------------------------------------------
-- Una fila por intento. "clave" identifica el par (acción + quién): por
-- ejemplo 'vender_stock:190.12.34.56' o 'crear_cliente:190.12.34.56'. No se
-- guarda nada del contenido de la llamada, solo que ocurrió y cuándo — lo
-- mínimo necesario para contar.
create table if not exists limite_llamadas (
  id bigint generated always as identity primary key,
  clave text not null,
  creado_en timestamptz not null default now()
);

-- Índice compuesto: toda consulta de este archivo filtra por clave y por
-- ventana de tiempo reciente, así que ambas columnas van juntas.
create index if not exists idx_limite_llamadas_clave_fecha
  on limite_llamadas (clave, creado_en desc);

-- Nadie necesita leer ni escribir esta tabla directamente desde el cliente:
-- solo la tocan las funciones RPC (que corren con los privilegios del
-- definidor, ver "security definer" más abajo). Se bloquea el acceso directo
-- por RLS sin ninguna política, dejando la tabla inaccesible vía PostgREST.
alter table limite_llamadas enable row level security;

-- ---------------------------------------------------------------------------
-- 2) Identificador del llamador
-- ---------------------------------------------------------------------------
-- Supabase (PostgREST) expone los headers de la request entrante en
-- current_setting('request.headers', true). Se usa x-forwarded-for, que es
-- el que arma la infraestructura de Supabase con la IP real del cliente.
-- Si por algún motivo no viene (llamada interna, headers vacíos), se agrupa
-- todo bajo 'sin-ip' en vez de fallar — más vale un límite compartido para
-- ese caso raro que romper la función.
create or replace function fn_identificador_llamador()
returns text
language plpgsql
stable
as $$
declare
  v_headers json;
  v_ip text;
begin
  begin
    v_headers := current_setting('request.headers', true)::json;
  exception when others then
    v_headers := null;
  end;
  if v_headers is null then
    return 'sin-ip';
  end if;
  v_ip := coalesce(
    split_part(v_headers->>'x-forwarded-for', ',', 1),
    v_headers->>'cf-connecting-ip'
  );
  return coalesce(nullif(trim(v_ip), ''), 'sin-ip');
end;
$$;

-- ---------------------------------------------------------------------------
-- 3) Chequeo de límite, reutilizable desde cualquier RPC
-- ---------------------------------------------------------------------------
-- Ventana deslizante simple: cuenta cuántas llamadas con esa clave hubo en
-- los últimos p_ventana_segundos. Si no se pasó el máximo, registra esta
-- llamada y devuelve true (puede seguir). Si se pasó, devuelve false SIN
-- registrar una llamada nueva (para no seguir empujando la ventana).
--
-- security definer: corre con los privilegios de quien la creó (no del rol
-- anon que la invoca), así puede escribir en limite_llamadas aunque esa
-- tabla no tenga políticas RLS para anon. Se fija search_path por seguridad,
-- igual que en las funciones de credenciales.
create or replace function fn_verificar_limite(
  p_accion text,
  p_max_intentos int,
  p_ventana_segundos int
)
returns boolean
language plpgsql
security definer
set search_path = public
as $$
declare
  v_clave text;
  v_conteo int;
begin
  v_clave := p_accion || ':' || fn_identificador_llamador();

  select count(*) into v_conteo
  from limite_llamadas
  where clave = v_clave
    and creado_en > now() - make_interval(secs => p_ventana_segundos);

  if v_conteo >= p_max_intentos then
    return false;
  end if;

  insert into limite_llamadas (clave) values (v_clave);
  return true;
end;
$$;

-- Ejemplo de uso dentro de una RPC (así lo usan vender_stock y las funciones
-- de recuperación de clave):
--
--   if not fn_verificar_limite('vender_stock', 30, 60) then
--     return jsonb_build_object('ok', false, 'motivo', 'limite_excedido');
--   end if;

-- ---------------------------------------------------------------------------
-- 4) Índices en las tablas de historial
-- ---------------------------------------------------------------------------
-- La app carga el historial con
--   .order('creado_en', { ascending:false }).limit(HISTORIAL_LIMITE_CARGA)
-- Sin índice, eso es un escaneo completo de la tabla ordenado en memoria
-- cada vez que alguien abre Ventas o Reportes. Con pocas filas no se nota;
-- apenas empiece a crecer el historial, sí.
create index if not exists idx_ventas_registro_creado_en
  on ventas_registro (creado_en desc);

create index if not exists idx_movimientos_registro_creado_en
  on movimientos_registro (creado_en desc);

-- ---------------------------------------------------------------------------
-- 5) Limpieza periódica de limite_llamadas
-- ---------------------------------------------------------------------------
-- Sin esto, la tabla crece para siempre (una fila por venta/llamada exitosa).
-- Basta con no guardar nada de más de 1 hora: ninguna ventana de este
-- archivo pasa ese tamaño.
create or replace function fn_limpiar_limite_llamadas()
returns void
language sql
security definer
set search_path = public
as $$
  delete from limite_llamadas where creado_en < now() - interval '1 hour';
$$;

-- Con pg_cron habilitado, la limpieza corre sola cada 15 minutos. Sin pg_cron,
-- este bloque no hace nada (no rompe la migración) y la limpieza se puede
-- ejecutar a mano con select fn_limpiar_limite_llamadas();
do $$
begin
  if exists (select 1 from pg_extension where extname = 'pg_cron') then
    perform cron.schedule(
      'limpiar_limite_llamadas',
      '*/15 * * * *',
      $cron$ select fn_limpiar_limite_llamadas(); $cron$
    );
  end if;
exception when others then
  -- pg_cron no disponible en este plan/proyecto: no es crítico, se ignora.
  null;
end $$;
