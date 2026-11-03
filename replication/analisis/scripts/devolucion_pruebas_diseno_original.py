"""Devolucion del tribunal, observacion 1 -- Que devolvio la consulta del diseno original (seccion 3.12).

El diseno original pedia a la NVD las vulnerabilidades de cada activo con cpeName. El orquestador
conserva tres ejecuciones reales de esa consulta: la 1 (10/08) y la 2 (11/08), con los identificadores
del inventario antes de la correccion, y la 3 (22/08), despues de la correccion. Este script lee, de
cada una, los parametros de la consulta y lo que la NVD devolvio para cada activo.

No necesita Docker: recorre el respaldo de la base interna de n8n (formato propio de pg_dump) y
descomprime solo la tabla de datos de ejecucion, hasta encontrar las tres ejecuciones.

Entrada: data/raw/respaldo_2026-10-23/n8n_internal.dump
Salida:  data/cleaned/devolucion_pruebas_diseno_original/por_activo.csv, resumen.csv
"""
import csv
import json
import re
import zlib
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DUMP = RAIZ / "data" / "raw" / "respaldo_2026-10-23" / "n8n_internal.dump"
SALIDA = RAIZ / "data" / "cleaned" / "devolucion_pruebas_diseno_original"
EJECUCIONES = {"1": "2026-08-10", "2": "2026-08-11", "3": "2026-08-22"}
BLOQUE_DATOS = 4667  # dumpId de execution_data en el respaldo del 23/10
BARRA = chr(92)
ESCAPES = {"n": "\n", "t": "\t", "r": "\r", BARRA: BARRA, "b": "\b", "f": "\f", "v": "\v"}
PATRON_ESCAPE = re.compile(BARRA + BARRA + "(.)", re.S)


def entero(buf, i):
    signo, valor = buf[i], int.from_bytes(buf[i + 1:i + 5], "little")
    return (-valor if signo else valor), i + 5


def lineas_de_la_tabla(buf):
    """Recorre las lineas COPY de la tabla, descomprimiendo el bloque por partes."""
    marca = bytes([1, 0]) + BLOQUE_DATOS.to_bytes(4, "little")
    inicio = buf.rfind(marca)
    assert inicio >= 0, "no se encontro el bloque de datos de ejecucion"
    i = inicio + 6
    d = zlib.decompressobj()
    resto = b""
    while True:
        tam, i = entero(buf, i)
        if tam <= 0:
            return
        resto += d.decompress(buf[i:i + tam])
        i += tam
        *completas, resto = resto.split(b"\n")
        yield from completas


def desescapar(b):
    return PATRON_ESCAPE.sub(lambda m: ESCAPES.get(m.group(1), m.group(1)), b.decode("utf-8", "replace"))


def leer_ejecucion(columnas):
    flujo = json.loads(desescapar(columnas[1]))
    nodo = next(n for n in flujo["nodes"] if n["name"] == "Query NVD per CPE")
    parametros = {p["name"].lstrip("="): p["value"] for p in nodo["parameters"]["queryParameters"]["parameters"]}
    plano = json.loads(desescapar(columnas[2]))

    def v(x):  # el historial de n8n referencia cada valor por su posicion en la lista
        return plano[int(x)] if isinstance(x, str) and x.isdigit() and int(x) < len(plano) else x

    corridas = v(v(plano[0]["resultData"])["runData"])
    filas = {}
    for nombre in ("Fetch Assets", "Query NVD per CPE"):
        salida = v(v(v(v(corridas[nombre])[0])["data"])["main"])
        for i, item in enumerate(v(salida[0])):
            js = v(v(item)["json"])
            if nombre == "Fetch Assets":
                filas[i] = {"hostname": v(js["hostname"]), "cpe": v(js["cpe"])}
            else:
                filas[i]["devueltas"] = v(js["totalResults"])
    return parametros, list(filas.values())


def main():
    buf = DUMP.read_bytes()
    pendientes = set(EJECUCIONES)
    por_activo, resumen = [], []
    for linea in lineas_de_la_tabla(buf):
        eid = linea[:12].split(b"\t", 1)[0].decode("ascii", "replace")
        if eid not in pendientes:
            continue
        parametros, filas = leer_ejecucion(linea.split(b"\t"))
        for f in filas:
            por_activo.append({"ejecucion": eid, "fecha": EJECUCIONES[eid], **f})
        resumen.append({"ejecucion": eid, "fecha": EJECUCIONES[eid],
                        "parametros": json.dumps(parametros, ensure_ascii=False),
                        "activos": len(filas),
                        "activos_vacios": sum(f["devueltas"] == 0 for f in filas),
                        "activos_microsoft": sum(":microsoft:" in f["cpe"] for f in filas),
                        "microsoft_vacios": sum(":microsoft:" in f["cpe"] and f["devueltas"] == 0 for f in filas),
                        "pares_devueltos": sum(f["devueltas"] for f in filas)})
        pendientes.discard(eid)
        if not pendientes:
            break
    SALIDA.mkdir(parents=True, exist_ok=True)
    por_activo.sort(key=lambda f: (f["ejecucion"], f["hostname"]))
    resumen.sort(key=lambda f: f["ejecucion"])
    for nombre, filas in (("por_activo.csv", por_activo), ("resumen.csv", resumen)):
        with (SALIDA / nombre).open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(filas[0]))
            w.writeheader()
            w.writerows(filas)
    for r in resumen:
        print(r)


if __name__ == "__main__":
    main()
