#!/usr/bin/env python3
"""
Estrés funcional: cientos de operaciones mezcladas, en paralelo, contra Postgres.

Mezcla ventas de una vendedora, ventas al fiado y mermas de una administradora,
y reenvíos de ventas ya enviadas (como harían los reintentos de la app). Cuando
termina, comprueba invariantes contables que deben cuadrar EXACTAMENTE:

  1. stock final = stock inicial − unidades realmente aplicadas, y nunca negativo
  2. unidades que quedan en los lotes = stock final
  3. costo total registrado = costo FIFO calculado de forma independiente
  4. historial: una venta por cada venta aplicada, un movimiento por cada línea
  5. saldo de los clientes = suma de los fiados aplicados
  6. cada id de operación se aplicó como máximo una vez (idempotencia)

Uso: DATABASE_URL=postgresql://... python3 tests/estres.py
Variables: OPS (por defecto 400), HILOS (por defecto 24), SEMILLA (por defecto 7).
"""
import json, os, random, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor

DB = os.environ.get("DATABASE_URL", "postgresql://postgres:postgres@127.0.0.1:54322/postgres")
OPS = int(os.environ.get("OPS", "400"))
HILOS = int(os.environ.get("HILOS", "24"))
random.seed(int(os.environ.get("SEMILLA", "7")))

PRODUCTOS = [f"est-p{i}" for i in range(1, 6)]
CLIENTES = [f"est-c{i}" for i in range(1, 4)]
STOCK_INICIAL = 200            # por producto: 100 unidades a $100 y 100 a $200
PRECIO = 1000


def psql(sql, tolerar=False):
    r = subprocess.run(["psql", DB, "-X", "-q", "-t", "-A", "-v", "ON_ERROR_STOP=1", "-c", sql],
                       capture_output=True, text=True)
    if r.returncode != 0 and not tolerar:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()


def como(usuario, llamada):
    claims = json.dumps({"role": "authenticated", "app_metadata": {"usuario_id": usuario}})
    # una IP distinta por operación: así el límite de llamadas por IP (que tiene sus propias
    # pruebas) no frena el estrés, y se ejercita de verdad la lógica de ventas
    ip = ".".join(str(b) for b in os.urandom(4))
    headers = json.dumps({"cf-connecting-ip": ip})
    return (f"begin; set local role authenticated; set local request.jwt.claims = '{claims}'; "
            f"set local request.headers = '{headers}'; select ({llamada})::text; commit;")


def costo_fifo(q):
    return 100 * min(q, 100) + 200 * max(q - 100, 0)


def preparar():
    psql("alter table ventas_registro disable trigger trg_notificar_venta_nueva")
    for k in ("productos", "lotes", "clientes", "usuarios"):
        psql(f"insert into app_data (key, value) values ('{k}', '[]') on conflict (key) do nothing")
    prod = [{"id": p, "nombre": p, "precio": PRECIO, "stock": STOCK_INICIAL, "stockMinimo": 0} for p in PRODUCTOS]
    lotes = []
    for p in PRODUCTOS:
        lotes += [{"id": f"{p}-l1", "productoId": p, "cantidadRestante": 100, "costoUnitario": 100, "fecha": 1},
                  {"id": f"{p}-l2", "productoId": p, "cantidadRestante": 100, "costoUnitario": 200, "fecha": 2}]
    cli = [{"id": c, "nombre": c, "saldo": 0} for c in CLIENTES]
    usu = [{"id": "estvend", "nombre": "Caja", "rol": "vendedor", "activo": True},
           {"id": "estadmin", "nombre": "Dueña", "rol": "admin", "activo": True}]
    for k, v in (("productos", prod), ("lotes", lotes), ("clientes", cli), ("usuarios", usu)):
        psql(f"update app_data set value = value || $j${json.dumps(v)}$j$::jsonb where key = '{k}'")


def limpiar():
    psql("""
delete from ventas_registro where id like 'est-%';
delete from movimientos_registro where id like 'est-%' or data ->> 'ventaId' like 'est-%';
update app_data set value = (select coalesce(jsonb_agg(e), '[]'::jsonb) from jsonb_array_elements(value) e
                             where e ->> 'id' not like 'est-%' and e ->> 'id' not in ('estvend', 'estadmin'))
 where key in ('productos', 'lotes', 'clientes', 'usuarios');
delete from limite_llamadas where clave like 'registrar_venta:%' or clave like 'generar_codigo%';
alter table ventas_registro enable trigger trg_notificar_venta_nueva;
""", tolerar=True)


def generar_operaciones():
    ops = []
    for i in range(OPS):
        n = i % 100
        if n < 70:     # ventas de la vendedora
            tipo = "venta"
        elif n < 85:   # ventas al fiado (solo administradora)
            tipo = "fiado"
        else:          # mermas (solo administradora)
            tipo = "merma"
        p = random.choice(PRODUCTOS)
        q = random.randint(1, 3) if tipo != "merma" else 1
        op = {"id": f"est-{tipo}-{i:04d}", "tipo": tipo, "producto": p, "cantidad": q}
        if tipo == "fiado":
            op["cliente"] = random.choice(CLIENTES)
        ops.append(op)
    # reenvíos: 15 % de las operaciones se envían una segunda vez, mezcladas
    repetidas = random.sample(ops, int(OPS * 0.15))
    todas = ops + repetidas
    random.shuffle(todas)
    return todas


def ejecutar(op):
    if op["tipo"] == "merma":
        mov = {"id": op["id"], "productoId": op["producto"], "cantidad": op["cantidad"], "tipo": "salida", "motivo": "estrés"}
        sql = como("estadmin", f"registrar_salida_stock($j${json.dumps(mov)}$j$::jsonb)")
    else:
        metodo = "fiado" if op["tipo"] == "fiado" else "efectivo"
        monto = op["cantidad"] * PRECIO
        venta = {"id": op["id"], "operador": "estrés", "pagos": [{"metodo": metodo, "monto": monto}],
                 "items": [{"productoId": op["producto"], "nombre": op["producto"], "cantidad": op["cantidad"], "precioUnitario": PRECIO}]}
        if op["tipo"] == "fiado":
            venta["clienteId"] = op["cliente"]
        usuario = "estadmin" if op["tipo"] == "fiado" else "estvend"
        sql = como(usuario, f"registrar_venta($j${json.dumps(venta)}$j$::jsonb, false)")
    try:
        d = json.loads(psql(sql).splitlines()[-1])
    except Exception as e:
        return {**op, "resultado": "error", "detalle": str(e)[:200]}
    if d.get("duplicada"):
        res = "duplicada"
    elif d.get("ok"):
        res = "aplicada"
    else:
        res = "rechazada:" + str(d.get("motivo"))
    return {**op, "resultado": res}


falla = False
def verificar(nombre, esperado, obtenido):
    global falla
    ok = esperado == obtenido
    falla = falla or not ok
    print(("ok    - " if ok else "FALLA - ") + nombre + ("" if ok else f" (esperado: {esperado}, obtenido: {obtenido})"))


def main():
    limpiar()
    preparar()
    try:
        ops = generar_operaciones()
        print(f"{len(ops)} operaciones ({OPS} únicas + {len(ops) - OPS} reenvíos) en {HILOS} hilos…")
        t0 = time.time()
        with ThreadPoolExecutor(HILOS) as ex:
            res = list(ex.map(ejecutar, ops))
        seg = time.time() - t0
        print(f"terminó en {seg:.1f} s ({len(ops) / seg:.0f} operaciones/s)\n")

        resumen = {}
        for r in res:
            resumen[r["resultado"]] = resumen.get(r["resultado"], 0) + 1
        print("resultados:", json.dumps(resumen, ensure_ascii=False), "\n")

        errores = [r for r in res if r["resultado"] == "error"]
        verificar("ninguna operación terminó en error inesperado", 0, len(errores))
        for e in errores[:3]:
            print("   ", e["id"], e.get("detalle"))

        # lo realmente aplicado, una sola vez por id
        por_id = {}
        for r in res:
            if r["resultado"] == "aplicada":
                por_id.setdefault(r["id"], []).append(r)
        verificar("cada id de operación se aplicó como máximo una vez", 0, sum(1 for v in por_id.values() if len(v) > 1))

        aplicadas = [v[0] for v in por_id.values()]
        q = {p: sum(a["cantidad"] for a in aplicadas if a["producto"] == p) for p in PRODUCTOS}
        ventas = [a for a in aplicadas if a["tipo"] in ("venta", "fiado")]
        mermas = [a for a in aplicadas if a["tipo"] == "merma"]

        stock = {p: int(float(psql(f"select e ->> 'stock' from app_data, jsonb_array_elements(value) e where key = 'productos' and e ->> 'id' = '{p}'"))) for p in PRODUCTOS}
        verificar("stock final = inicial − unidades aplicadas (todos los productos)",
                  {p: STOCK_INICIAL - q[p] for p in PRODUCTOS}, stock)
        verificar("ningún stock quedó negativo", 0, sum(1 for v in stock.values() if v < 0))

        lotes = {p: int(float(psql(f"select coalesce(sum((e ->> 'cantidadRestante')::numeric), 0) from app_data, jsonb_array_elements(value) e where key = 'lotes' and e ->> 'productoId' = '{p}'"))) for p in PRODUCTOS}
        verificar("unidades en los lotes = stock (el FIFO y el stock nunca se descuadran)", stock, lotes)

        costos = {}
        filas = psql("""select coalesce(v.item ->> 'productoId', ''), sum((v.item ->> 'costoTotal')::numeric)
                        from (select jsonb_array_elements(data -> 'items') item from ventas_registro where id like 'est-%') v group by 1""")
        for linea in filas.splitlines():
            p, c = linea.split("|")
            costos[p] = costos.get(p, 0) + float(c)
        filas = psql("select data ->> 'productoId', sum((data ->> 'costoTotal')::numeric) from movimientos_registro where id like 'est-merma-%' group by 1")
        for linea in filas.splitlines():
            if linea:
                p, c = linea.split("|")
                costos[p] = costos.get(p, 0) + float(c)
        verificar("costo registrado = costo FIFO calculado de forma independiente",
                  {p: float(costo_fifo(q[p])) for p in PRODUCTOS if q[p] > 0}, {p: costos.get(p, 0.0) for p in PRODUCTOS if q[p] > 0})

        verificar("historial: una venta por cada venta aplicada", len(ventas), int(psql("select count(*) from ventas_registro where id like 'est-%'")))
        verificar("historial: un movimiento por cada línea de venta", len(ventas), int(psql("select count(*) from movimientos_registro where data ->> 'ventaId' like 'est-%'")))
        verificar("historial: un movimiento por cada merma", len(mermas), int(psql("select count(*) from movimientos_registro where id like 'est-merma-%'")))

        saldo_esperado = {c: sum(a["cantidad"] * PRECIO for a in ventas if a["tipo"] == "fiado" and a["cliente"] == c) for c in CLIENTES}
        saldo = {c: int(float(psql(f"select e ->> 'saldo' from app_data, jsonb_array_elements(value) e where key = 'clientes' and e ->> 'id' = '{c}'"))) for c in CLIENTES}
        verificar("saldo de cada cliente = suma de sus fiados aplicados", saldo_esperado, saldo)
    finally:
        limpiar()
    sys.exit(1 if falla else 0)


main()
