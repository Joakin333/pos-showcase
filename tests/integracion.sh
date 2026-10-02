#!/usr/bin/env bash
# ============================================================================
# Integración de punta a punta, por HTTP, igual que la app:
#   login con la Edge Function iniciar-sesion → canje del token en Supabase
#   Auth → ventas por la API REST con la sesión obtenida.
#
# Requiere el stack local levantado (supabase start) y las Edge Functions
# sirviendo (supabase functions serve). Lee las URLs y llaves de:
#   API_URL, ANON_KEY, DB_URL   (las entrega `supabase status -o env`)
# ============================================================================
set -euo pipefail

: "${API_URL:?falta API_URL}" "${ANON_KEY:?falta ANON_KEY}" "${DB_URL:?falta DB_URL}"
CLAVE='clave-de-prueba-123'
falla=0
verificar() { if [ "$2" = "$3" ]; then echo "ok    - $1"; else echo "FALLA - $1 (esperado: $2, obtenido: $3)"; falla=1; fi; }
json() { python3 -c "import sys,json; d=json.load(sys.stdin); print($1)"; }
psql_() { psql "$DB_URL" -X -q -t -A -v ON_ERROR_STOP=1 "$@"; }

# ---- datos: una vendedora con una clave conocida y un producto -----------------
BUNDLE=$(python3 - <<PY
import hashlib, os, json
sal = os.urandom(16).hex()
valor = hashlib.pbkdf2_hmac('sha256', b'$CLAVE', bytes.fromhex(sal), 100000).hex()
print(json.dumps({"algo": "pbkdf2", "sal": sal, "iter": 100000, "valor": valor}))
PY
)
limpiar() {
  psql_ <<'SQL' >/dev/null
delete from ventas_registro where id like 'int-%';
delete from movimientos_registro where id like 'mv-int-%';
delete from credenciales where usuario_id = 'intvend01';
delete from intentos_credencial where usuario_id = 'intvend01';
delete from auth.users where email = 'intvend01@usuarios.pos.invalid';
update app_data set value = (select coalesce(jsonb_agg(e), '[]'::jsonb) from jsonb_array_elements(value) e
                             where e ->> 'id' not in ('intvend01', 'int-prod'))
 where key in ('productos', 'usuarios');
alter table ventas_registro enable trigger trg_notificar_venta_nueva;
SQL
}
trap limpiar EXIT
psql_ <<SQL >/dev/null
alter table ventas_registro disable trigger trg_notificar_venta_nueva;
insert into app_data (key, value) values ('productos', '[]'), ('usuarios', '[]') on conflict (key) do nothing;
update app_data set value = value || '[{"id":"intvend01","nombre":"Caja","rol":"vendedor","activo":true}]' where key = 'usuarios';
update app_data set value = value || '[{"id":"int-prod","nombre":"Producto","precio":1000,"stock":10}]' where key = 'productos';
insert into credenciales (usuario_id, clave) values ('intvend01', '$BUNDLE'::jsonb)
on conflict (usuario_id) do update set clave = excluded.clave;
SQL

H=(-H "apikey: $ANON_KEY" -H "Content-Type: application/json")
login() { curl -s -X POST "$API_URL/functions/v1/iniciar-sesion" "${H[@]}" -d "{\"usuario_id\":\"intvend01\",\"clave\":\"$1\"}"; }

# ---- login ---------------------------------------------------------------------
verificar "clave incorrecta: rechazada con intentos restantes" "False 4" \
  "$(login 'otra-clave' | json "d.get('ok'), d.get('intentosRestantes')")"

TOKEN_HASH=$(login "$CLAVE" | json "d.get('token_hash', '')")
verificar "clave correcta: entrega un token de un solo uso" "si" "$([ -n "$TOKEN_HASH" ] && echo si || echo no)"

canjear() { curl -s -X POST "$API_URL/auth/v1/verify" "${H[@]}" -d "{\"type\":\"magiclink\",\"token_hash\":\"$TOKEN_HASH\"}"; }
ACCESS=$(canjear | json "d.get('access_token', '')")
verificar "el token se canjea por una sesión de Supabase Auth" "si" "$([ -n "$ACCESS" ] && echo si || echo no)"
verificar "el mismo token no se puede reutilizar" "no" "$(canjear | json "'si' if d.get('access_token') else 'no'")"

USUARIO_JWT=$(python3 -c "
import base64, json, sys
p = sys.argv[1].split('.')[1]; p += '=' * (-len(p) % 4)
print(json.loads(base64.urlsafe_b64decode(p))['app_metadata'].get('usuario_id'))" "$ACCESS")
verificar "el JWT lleva el usuario en app_metadata (solo lo escribe el servidor)" "intvend01" "$USUARIO_JWT"

# ---- API REST con y sin sesión ---------------------------------------------------
claves() { curl -s "$API_URL/rest/v1/app_data?select=key&order=key" "$@" | json "','.join(x['key'] for x in d)"; }
verificar "sin sesión: solo se ve la lista de usuarios" "usuarios" "$(claves -H "apikey: $ANON_KEY")"
verificar "con sesión: se ve el catálogo" "si" \
  "$(claves -H "apikey: $ANON_KEY" -H "Authorization: Bearer $ACCESS" | grep -q productos && echo si || echo no)"

VENTA='{"p_offline":false,"p_venta":{"id":"int-venta-1","operador":"Caja","pagos":[{"metodo":"efectivo","monto":2000}],"items":[{"productoId":"int-prod","nombre":"x","cantidad":2,"precioUnitario":1000}]}}'
rpc() { curl -s -X POST "$API_URL/rest/v1/rpc/registrar_venta" "${H[@]}" "$@" -d "$VENTA"; }
verificar "sin sesión: registrar_venta está bloqueada" "42501" "$(rpc | json "d.get('code')")"
verificar "con sesión: la venta se registra" "True None" \
  "$(rpc -H "Authorization: Bearer $ACCESS" | json "d.get('ok'), d.get('duplicada')")"
verificar "la misma venta otra vez vuelve como duplicada" "True True" \
  "$(rpc -H "Authorization: Bearer $ACCESS" | json "d.get('ok'), d.get('duplicada')")"
verificar "el stock bajó una sola vez (10 → 8)" "8" \
  "$(psql_ -c "select e ->> 'stock' from app_data, jsonb_array_elements(value) e where key = 'productos' and e ->> 'id' = 'int-prod'")"

exit $falla
