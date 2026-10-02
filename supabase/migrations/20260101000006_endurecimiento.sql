-- ============================================================================
-- 006 · Endurecimiento: cerrar funciones que la app no usa
-- ============================================================================
--   1) Quita el permiso de ejecución desde la API a las funciones de respaldo,
--      restauración y limpieza (las corre pg_cron o se usan desde el SQL
--      Editor) y a las funciones rpc_* de un login anterior.
--   2) fn_restaurar_respaldo: restaura un respaldo de app_data por id.
--      Uso: select fn_restaurar_respaldo(<id>);
--   3) Programa la limpieza de limite_llamadas cada 15 minutos.
--   4) Fija search_path en vender_stock y fn_identificador_llamador.
--   5) Elimina índices duplicados de historial, si existen.
-- ============================================================================

revoke execute on function public.fn_respaldo_diario()              from public, anon, authenticated;
revoke execute on function public.fn_limpiar_limite_llamadas()      from public, anon, authenticated;
-- Las 8 funciones rpc_* son de un login anterior y en una base nueva no
-- existen: cada revoke va dentro de to_regprocedure(...) para que la migración
-- funcione en ambos casos.
do $$
begin
  if to_regprocedure('public.rpc_borrar_respuesta(text)') is not null then
    revoke execute on function public.rpc_borrar_respuesta(text) from public, anon, authenticated;
  end if;
  if to_regprocedure('public.rpc_eliminar_credencial(text)') is not null then
    revoke execute on function public.rpc_eliminar_credencial(text) from public, anon, authenticated;
  end if;
  if to_regprocedure('public.rpc_guardar_clave(text, text, text, text, integer)') is not null then
    revoke execute on function public.rpc_guardar_clave(text, text, text, text, integer) from public, anon, authenticated;
  end if;
  if to_regprocedure('public.rpc_guardar_respuesta(text, text, text, text, integer)') is not null then
    revoke execute on function public.rpc_guardar_respuesta(text, text, text, text, integer) from public, anon, authenticated;
  end if;
  if to_regprocedure('public.rpc_sal_login(text)') is not null then
    revoke execute on function public.rpc_sal_login(text) from public, anon, authenticated;
  end if;
  if to_regprocedure('public.rpc_sal_respuesta(text)') is not null then
    revoke execute on function public.rpc_sal_respuesta(text) from public, anon, authenticated;
  end if;
  if to_regprocedure('public.rpc_verificar_login(text, text)') is not null then
    revoke execute on function public.rpc_verificar_login(text, text) from public, anon, authenticated;
  end if;
  if to_regprocedure('public.rpc_verificar_respuesta(text, text)') is not null then
    revoke execute on function public.rpc_verificar_respuesta(text, text) from public, anon, authenticated;
  end if;
end $$;

create or replace function public.fn_restaurar_respaldo(p_id bigint)
returns void
language plpgsql
security definer
set search_path to 'public'
as $function$
declare
  v_contenido jsonb;
  v_key text;
begin
  select contenido into v_contenido from respaldos_app_data where id = p_id;
  if v_contenido is null then
    raise exception 'No existe un respaldo con ese id.';
  end if;

  for v_key in select jsonb_object_keys(v_contenido)
  loop
    insert into app_data (key, value, updated_at)
    values (v_key, v_contenido->v_key, now())
    on conflict (key) do update set value = excluded.value, updated_at = excluded.updated_at;
  end loop;
end;
$function$;
revoke execute on function public.fn_restaurar_respaldo(bigint) from public, anon, authenticated;

do $$
begin
  if not exists (select 1 from cron.job where jobname = 'limpiar_limite_llamadas') then
    perform cron.schedule('limpiar_limite_llamadas', '*/15 * * * *', $cron$ select public.fn_limpiar_limite_llamadas(); $cron$);
  end if;
end $$;

-- 4) search_path fijo
alter function public.vender_stock(jsonb)         set search_path = public;
alter function public.fn_identificador_llamador() set search_path = public;

-- 5) Índices duplicados (no hace nada si ya no existen)
drop index if exists public.idx_ventas_creado_en;
drop index if exists public.idx_movimientos_creado_en;
