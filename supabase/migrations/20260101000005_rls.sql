-- ============================================================================
-- 005 · Row Level Security: primera limpieza de políticas
-- ============================================================================
-- Reemplaza políticas "acceso total" y duplicadas por una política por
-- comando, limitada a lo que la app realmente usa:
--   app_data              → select, insert, update (nunca delete)
--   ventas_registro       → select, insert          (historial: sin update/delete)
--   movimientos_registro  → select, insert          (historial: sin update/delete)
--
-- Las tablas de credenciales y límites quedan con RLS activo y sin políticas:
-- nadie las toca directo por la API, solo funciones security definer.
--
-- Estas políticas todavía aceptan al rol anónimo; la migración 009 las
-- reemplaza por políticas que exigen sesión y distinguen roles.
-- ============================================================================

-- ---------------------------------------------------------------------------
-- app_data: catálogo/clientes/lotes/etc., guardados como JSON por clave.
-- ---------------------------------------------------------------------------
alter table app_data enable row level security;

drop policy if exists "Acceso total app_data" on app_data;
drop policy if exists "Permitir insercion app_data" on app_data;
drop policy if exists "acceso publico insert" on app_data;
drop policy if exists "app_data_insert" on app_data;
drop policy if exists "Permitir lectura app_data" on app_data;
drop policy if exists "acceso publico select" on app_data;
drop policy if exists "app_data_select" on app_data;
drop policy if exists "Permitir actualizacion app_data" on app_data;
drop policy if exists "acceso publico update" on app_data;
drop policy if exists "app_data_update" on app_data;

create policy "app_data_select" on app_data
  for select to anon, authenticated using (true);
create policy "app_data_insert" on app_data
  for insert to anon, authenticated with check (true);
create policy "app_data_update" on app_data
  for update to anon, authenticated using (true) with check (true);
-- Sin política de delete a propósito: nadie puede borrar una clave de
-- app_data por la API. Si alguna vez hace falta borrar una, se hace a mano
-- desde el SQL Editor (con la llave de servicio), nunca desde el cliente.

-- ---------------------------------------------------------------------------
-- ventas_registro: historial de ventas. Registro de auditoría → solo se
-- agrega, nunca se edita ni se borra por API.
-- ---------------------------------------------------------------------------
alter table ventas_registro enable row level security;

drop policy if exists "Acceso total ventas_registro" on ventas_registro;
drop policy if exists "Permitir insercion ventas" on ventas_registro;
drop policy if exists "ventas_insert" on ventas_registro;
drop policy if exists "Solo lectura ventas" on ventas_registro;
drop policy if exists "ventas_select" on ventas_registro;

create policy "ventas_registro_select" on ventas_registro
  for select to anon, authenticated using (true);
create policy "ventas_registro_insert" on ventas_registro
  for insert to anon, authenticated with check (true);

-- ---------------------------------------------------------------------------
-- movimientos_registro: historial de movimientos de stock/caja. Mismo
-- criterio que ventas_registro.
-- ---------------------------------------------------------------------------
alter table movimientos_registro enable row level security;

drop policy if exists "Acceso total movimientos_registro" on movimientos_registro;
drop policy if exists "Permitir insercion movimientos" on movimientos_registro;
drop policy if exists "movimientos_insert" on movimientos_registro;
drop policy if exists "Solo lectura movimientos" on movimientos_registro;
drop policy if exists "movimientos_select" on movimientos_registro;

create policy "movimientos_registro_select" on movimientos_registro
  for select to anon, authenticated using (true);
create policy "movimientos_registro_insert" on movimientos_registro
  for insert to anon, authenticated with check (true);

-- ---------------------------------------------------------------------------
-- Tablas de credenciales y límites: RLS activado, sin ninguna política.
-- Con RLS encendido y cero políticas, Postgres deniega todo por defecto —
-- estas tablas quedan invisibles/intocables desde la API REST directa, y
-- solo se pueden usar desde dentro de una función "security definer"
-- (que corre con privilegios propios, no los del rol que la invoca).
-- ---------------------------------------------------------------------------
alter table credenciales enable row level security;
alter table credenciales_usuario enable row level security;
alter table intentos_credencial enable row level security;
alter table intentos_login enable row level security;
alter table limite_llamadas enable row level security;

-- ============================================================================
-- Verificación rápida después de ejecutar esto:
--   select tablename, policyname, cmd from pg_policies
--   where schemaname = 'public' order by tablename, cmd;
--
--   Debería mostrar exactamente 7 filas: 3 en app_data (select/insert/update),
--   2 en ventas_registro (select/insert) y 2 en movimientos_registro
--   (select/insert). Ninguna con cmd = 'ALL' ni 'DELETE'.
-- ============================================================================
