#!/usr/bin/env bash
# ============================================================================
# Concurrencia real: muchas conexiones a Postgres al mismo tiempo, como si
# fueran cajas distintas vendiendo en el mismo instante.
#
#   A) N ventas distintas compiten por la ÚLTIMA unidad de un producto.
#      Debe aplicarse exactamente 1; el resto, rechazadas por stock.
#   B) La MISMA venta (mismo id) llega M veces a la vez, como reintentos.
#      Debe aplicarse 1 y el resto volver como duplicadas; el stock baja 1 vez.
#
# Uso: DATABASE_URL=postgresql://... tests/concurrencia.sh
# ============================================================================
set -euo pipefail

DB="${DATABASE_URL:-postgresql://postgres:postgres@127.0.0.1:54322/postgres}"
N="${N:-20}"   # ventas compitiendo por la última unidad
M="${M:-10}"   # reintentos simultáneos de la misma venta
psql_() { psql "$DB" -X -q -t -A -v ON_ERROR_STOP=1 "$@"; }
falla=0
verificar() { # $1 descripción  $2 esperado  $3 obtenido
  if [ "$2" = "$3" ]; then echo "ok    - $1"; else echo "FALLA - $1 (esperado: $2, obtenido: $3)"; falla=1; fi
}

# ---- datos de prueba (con prefijo propio, se borran al final) -----------------
limpiar() {
  psql_ <<'SQL'
delete from ventas_registro where id like 'conc-%';
delete from movimientos_registro where id like 'mv-conc-%';
update app_data set value = (select coalesce(jsonb_agg(e), '[]'::jsonb) from jsonb_array_elements(value) e
                             where e ->> 'id' not like 'conc-%')
 where key in ('productos', 'usuarios');
alter table ventas_registro enable trigger trg_notificar_venta_nueva;
SQL
}
trap limpiar EXIT

psql_ <<'SQL'
alter table ventas_registro disable trigger trg_notificar_venta_nueva;
insert into app_data (key, value) values ('productos', '[]'), ('usuarios', '[]'), ('lotes', '[]')
on conflict (key) do nothing;
update app_data set value = value || '[{"id":"conc-ultima","nombre":"Última unidad","precio":1000,"stock":1},
                                       {"id":"conc-diez","nombre":"Diez","precio":1000,"stock":10}]'
 where key = 'productos';
update app_data set value = value || '[{"id":"conc-vend","nombre":"Caja","rol":"vendedor","activo":true}]'
 where key = 'usuarios';
SQL

# Una venta desde una conexión propia, con el rol y el JWT de la vendedora.
vender() { # $1 id de venta  $2 producto  $3 cantidad
  psql "$DB" -X -q -t -A <<SQL
begin;
set local role authenticated;
set local request.jwt.claims = '{"role":"authenticated","app_metadata":{"usuario_id":"conc-vend"}}';
select case
  when r ->> 'duplicada' = 'true' then 'duplicada'
  when r ->> 'ok' = 'true'        then 'aplicada'
  else coalesce(r ->> 'motivo', 'error') end
from (select registrar_venta(jsonb_build_object(
        'id', '$1', 'operador', 'Caja', 'pagos', '[{"metodo":"efectivo","monto":1000}]'::jsonb,
        'items', jsonb_build_array(jsonb_build_object('productoId', '$2', 'nombre', 'x',
                                                      'cantidad', $3, 'precioUnitario', 1000))),
      false) as r) t;
commit;
SQL
}
export -f vender; export DB

stock() { psql_ -c "select e ->> 'stock' from app_data, jsonb_array_elements(value) e where key = 'productos' and e ->> 'id' = '$1'"; }
contar() { grep -cx "$1" "$2" || true; }

# ---- A) N ventas por la última unidad ---------------------------------------------
echo "A) $N ventas simultáneas por la última unidad"
seq 1 "$N" | xargs -P "$N" -I{} bash -c 'vender conc-a-{} conc-ultima 1' > /tmp/conc_a.txt
sort /tmp/conc_a.txt | uniq -c
verificar "A: exactamente 1 venta aplicada" 1 "$(contar aplicada /tmp/conc_a.txt)"
verificar "A: el resto rechazadas por stock" "$((N - 1))" "$(contar stock_insuficiente /tmp/conc_a.txt)"
verificar "A: el stock queda en 0, nunca negativo" 0 "$(stock conc-ultima)"

# ---- B) la misma venta M veces a la vez ---------------------------------------------
echo "B) la misma venta enviada $M veces a la vez"
seq 1 "$M" | xargs -P "$M" -I{} bash -c 'vender conc-b-misma conc-diez 2' > /tmp/conc_b.txt
sort /tmp/conc_b.txt | uniq -c
verificar "B: exactamente 1 aplicada" 1 "$(contar aplicada /tmp/conc_b.txt)"
verificar "B: el resto reconocidas como duplicadas" "$((M - 1))" "$(contar duplicada /tmp/conc_b.txt)"
verificar "B: el stock bajó una sola vez (10 → 8)" 8 "$(stock conc-diez)"
verificar "B: una sola venta en el historial" 1 "$(psql_ -c "select count(*) from ventas_registro where id = 'conc-b-misma'")"

exit $falla
