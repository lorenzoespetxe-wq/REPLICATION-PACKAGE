"""Bloque 4 -- Reaplicacion de la via de inferencia al cierre, y diagnostico de las perdidas.

La reconsulta del bloque 1 volvio a aplicar solo la regla formal. Este script aplica la regla
de inferencia del artefacto sobre los nombres de fabricante y producto (bloque `affected` del
registro) en dos momentos, y los compara:

  al ingerir  lo que devolvio la NVD en cada corrida, leido del historial de ejecuciones del
              orquestador (base interna de n8n, solo lectura)
  hoy         una consulta nueva a la NVD sobre el mismo rango de publicacion

Control previo: con los datos del historial reconstruye, corrida por corrida, los pares que el
flujo debio persistir (formal primero; si no, inferencia; el primer registro de cada par gana,
como la consulta de existencia) y los compara con los pares de campana de la base. Si no
coinciden, la copia de la regla esta mal y el script se detiene.

Despues diagnostica las vulnerabilidades que la NVD vincula hoy por la via formal a un activo y
que el sistema nunca detecto (las 52 del bloque 1): por que la inferencia no las encontro al
ingerir, y si las encontraria hoy.

No escribe en la base ni toca el orquestador. La clave de la NVD es opcional (variable de
entorno NVD_API_KEY); sin ella la consulta es mas lenta.

Uso, desde la raiz del proyecto:
    python scripts/bloque4_reconsulta_inferencia.py                 # consulta nueva a la NVD
    python scripts/bloque4_reconsulta_inferencia.py --sin-consulta  # reusa la ultima guardada
"""
import argparse
import csv
import json
import os
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

from bloque1_estado_al_ingerir import decodificar, psql, vulnerabilidades

RAIZ = Path(__file__).resolve().parent.parent
RAW = RAIZ / "data" / "raw"
SALIDA = RAIZ / "data" / "cleaned" / "bloque4_reconsulta_inferencia"
CACHE_INGESTA = RAW / "afectados_al_ingerir.csv"
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
POR_PAGINA = 2000
INICIO, FIN = "2026-08-28T00:00:00.000", "2026-09-26T23:59:59.999"  # mismo rango que el bloque 1


# ---------- regla del nodo `Parse NVD Response`, copiada sin cambios de logica ----------

def normalizar(texto):
    return "".join(ch for ch in str(texto or "").lower() if ch.isascii() and ch.isalnum())


def palabras(*campos):
    tokens = re.split(r"[_\-.\s]+", "_".join(campos).lower())
    return "|".join(sorted(t for t in tokens if t and t != "*"))


def claves_cpe(cpe):
    p = str(cpe or "").split(":")
    if len(p) < 5 or p[1] != "2.3":
        return []
    version = p[5] if len(p) > 5 else "*"
    return [palabras(p[3], p[4]), palabras(p[3], p[4], version)]


def formal(claves_activo, cpes):
    claves = {k for c in cpes for k in claves_cpe(c)}
    return any(k in claves for k in claves_activo)


def inferencia(activo, afectados):
    """Devuelve (coincide, motivo). El motivo explica el fallo cuando no coincide."""
    textos = [(normalizar(v), normalizar(p)) for v, p in afectados]
    textos = [(v, p) for v, p in textos if v and p]
    if not textos:
        return False, "sin_nombres_del_fabricante"
    validos = [(v, p) for v, p in textos if len(v) >= 4 and len(p) >= 3]
    if not validos:
        return False, "nombres_bajo_el_umbral"
    av, ap = activo["vendor"], activo["product"]
    vendor_ok = False
    for v, p in validos:
        ok_v = bool(av) and (v in av or av in v)
        ok_p = bool(ap) and (p in ap or ap in p)
        if ok_v and ok_p:
            return True, "coincide"
        vendor_ok = vendor_ok or ok_v
    return False, "producto_no_coincide" if vendor_ok else "fabricante_no_coincide"


# ---------- carga ----------

def leer_csv(ruta):
    with ruta.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def activos():
    salida = {}
    for a in leer_csv(RAW / "activos_inventario.csv"):
        p = a["cpe"].split(":")
        salida[int(a["activo_id"])] = {"hostname": a["hostname"], "claves": claves_cpe(a["cpe"]),
                                       "vendor": normalizar(p[3]), "product": normalizar(p[4])}
    return salida


def extraer(cve):
    afectados = [[d.get("vendor", ""), d.get("product", "")]
                 for b in cve.get("affected", []) for d in b.get("affectedData", [])]
    cpes = [m["criteria"] for c in cve.get("configurations", []) for n in c.get("nodes", [])
            for m in n.get("cpeMatch", []) if m.get("criteria")]
    return afectados, cpes


def al_ingerir():
    """Por corrida y vulnerabilidad: nombres del fabricante y CPE tal como llegaron. Con cache."""
    if not CACHE_INGESTA.exists():
        filas = []
        for r in sorted(leer_csv(RAW / "corridas_campana.csv"), key=lambda r: r["ts_utc"]):
            ejec = psql("secops_research_db",
                        f"SELECT entidad_id FROM auditoria_acciones WHERE id={r['fila_auditoria']};").strip()
            datos = psql("n8n_internal", f'SELECT data FROM execution_data WHERE \\"executionId\\"={ejec};').strip()
            for v in vulnerabilidades(decodificar(datos)):
                afectados, cpes = extraer(v["cve"])
                filas.append({"fila_auditoria": r["fila_auditoria"], "ts_utc": r["ts_utc"],
                              "cve_id": v["cve"]["id"], "afectados": json.dumps(afectados, ensure_ascii=False),
                              "cpes": " ".join(cpes)})
            print(f"  corrida {r['fila_auditoria']}: leida", flush=True)
        with CACHE_INGESTA.open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["fila_auditoria", "ts_utc", "cve_id", "afectados", "cpes"])
            w.writeheader()
            w.writerows(filas)
    return leer_csv(CACHE_INGESTA)


def hoy():
    """Consulta nueva a la NVD sobre el rango completo. Guarda nombres y CPE de cada vulnerabilidad."""
    clave = os.environ.get("NVD_API_KEY", "")
    cab = {"User-Agent": "PoC_Tesis_SecOps/1.0 (reconsulta de inferencia)", "Accept": "application/json"}
    if clave:
        cab["apiKey"] = clave
    consulta_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    filas, totales, pagina = [], [], 0
    while True:
        params = {"pubStartDate": INICIO, "pubEndDate": FIN,
                  "resultsPerPage": POR_PAGINA, "startIndex": pagina * POR_PAGINA}
        req = urllib.request.Request(f"{URL}?{urllib.parse.urlencode(params)}", headers=cab)
        for intento in range(1, 7):
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    cuerpo = json.load(r)
                break
            except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
                print(f"  intento {intento} fallo ({getattr(e, 'code', e)})", flush=True)
                time.sleep(10 * intento)
        else:
            raise SystemExit("La NVD no respondio tras los reintentos.")
        totales.append(cuerpo["totalResults"])
        for v in cuerpo["vulnerabilities"]:
            afectados, cpes = extraer(v["cve"])
            filas.append({"cve_id": v["cve"]["id"], "vuln_status": v["cve"].get("vulnStatus", ""),
                          "afectados": json.dumps(afectados, ensure_ascii=False), "cpes": " ".join(cpes)})
        pagina += 1
        print(f"  pagina {pagina}: {len(filas)} de {cuerpo['totalResults']}", flush=True)
        if len(filas) >= cuerpo["totalResults"] or not cuerpo["vulnerabilities"]:
            break
        time.sleep(1 if clave else 7)
    sello = consulta_utc[:10].replace("-", "")
    destino = RAW / "nvd_reconsulta"
    with (destino / f"afectados_{sello}.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["cve_id", "vuln_status", "afectados", "cpes"])
        w.writeheader()
        w.writerows(filas)
    meta = {"consulta_utc": consulta_utc, "pubStartDate": INICIO, "pubEndDate": FIN, "paginas": pagina,
            "recibidos": len(filas), "total_declarado_por_pagina": totales,
            "total_cambio_durante_el_recorrido": len(set(totales)) > 1, "con_clave": bool(clave)}
    (destino / f"meta_afectados_{sello}.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    return {f["cve_id"]: f for f in filas}, meta


def guardada():
    """La ultima consulta de hoy() guardada en disco, sin volver a pedirla."""
    destino = RAW / "nvd_reconsulta"
    ruta = sorted(destino.glob("afectados_*.csv"))[-1]
    meta = json.loads(sorted(destino.glob("meta_afectados_*.json"))[-1].read_text(encoding="utf-8"))
    return {f["cve_id"]: f for f in leer_csv(ruta)}, meta


def pares_de_la_base():
    sql = ("SELECT cve_id, activo_id, fuente_correlacion FROM telemetria_vulnerabilidades "
           "WHERE fecha_ingesta_pipeline >= '2026-08-30';")
    cmd = ["docker", "exec", "postgres_db", "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -At -F "," -c "{sql}"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return {(c, int(a)): f for c, a, f in (l.split(",") for l in texto.strip().splitlines())}


# ---------- calculo ----------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sin-consulta", action="store_true",
                    help="reusa la ultima consulta guardada en lugar de pedir una nueva")
    args = ap.parse_args()
    inv = activos()
    print("Leyendo el historial del orquestador...")
    ingesta = al_ingerir()

    # Control: reconstruir los pares persistidos.
    reconstruidos = {}
    for fila in ingesta:  # ya ordenado por corrida
        afectados, cpes = json.loads(fila["afectados"]), fila["cpes"].split()
        for aid, a in inv.items():
            if formal(a["claves"], cpes):
                via = "NVD"
            elif inferencia(a, afectados)[0]:
                via = "HEURISTICA"
            else:
                continue
            reconstruidos.setdefault((fila["cve_id"], aid), via)
    base = pares_de_la_base()
    iguales = reconstruidos == base
    print(f"Control: {len(reconstruidos)} pares reconstruidos, {len(base)} en la base, "
          f"identicos: {iguales}")
    if not iguales:
        solo_r = set(reconstruidos) - set(base)
        solo_b = set(base) - set(reconstruidos)
        via = sum(reconstruidos[k] != base[k] for k in set(base) & set(reconstruidos))
        print(f"  solo reconstruidos: {len(solo_r)} | solo base: {len(solo_b)} | via distinta: {via}")
        print("  ejemplos:", list(solo_r)[:5], list(solo_b)[:5])
        raise SystemExit("La regla no reproduce la base: no se sigue.")

    if args.sin_consulta:
        print("Usando la ultima consulta guardada...")
        actual, meta = guardada()
    else:
        print("Consultando la NVD hoy...")
        actual, meta = hoy()

    # Nombres del fabricante al ingerir: union de las corridas que vieron cada vulnerabilidad.
    afect_ing = {}
    for fila in ingesta:
        afect_ing.setdefault(fila["cve_id"], []).extend(json.loads(fila["afectados"]))

    # (a) Inferencia al ingerir contra inferencia hoy, sobre todos los pares posibles.
    cambios = Counter()
    detalle_cambios = []
    for cve, af in afect_ing.items():
        af_hoy = json.loads(actual[cve]["afectados"]) if cve in actual else []
        for aid, a in inv.items():
            antes, despues = inferencia(a, af)[0], inferencia(a, af_hoy)[0]
            if antes and despues:
                cambios["coincide_en_ambos"] += 1
            elif antes:
                cambios["coincidia_y_hoy_no"] += 1
                detalle_cambios.append((cve, a["hostname"], "perdida"))
            elif despues:
                cambios["no_coincidia_y_hoy_si"] += 1
                detalle_cambios.append((cve, a["hostname"], "ganada"))
    cambios["vulnerabilidades_con_nombres_distintos_hoy"] = sum(
        1 for cve, af in afect_ing.items()
        if cve in actual and set(map(tuple, json.loads(actual[cve]["afectados"]))) != set(map(tuple, af)))

    # (b) Las nunca detectadas con coincidencia formal al 30/09.
    detectados = set()
    for r in leer_csv(RAW / "corridas_campana.csv"):
        detectados |= set(r["ids"].split())
    reconsulta = {r["cve_id"]: r for r in leer_csv(RAW / "nvd_reconsulta" / "cves_20260930.csv")}
    perdidas = []
    for cve, r in reconsulta.items():
        if cve in detectados or cve not in afect_ing or not r["cpes"]:
            continue
        for aid, a in inv.items():
            if not formal(a["claves"], r["cpes"].split()):
                continue
            coincide_ing, motivo = inferencia(a, afect_ing[cve])
            af_hoy = json.loads(actual[cve]["afectados"]) if cve in actual else []
            perdidas.append({"cve_id": cve, "hostname": a["hostname"], "motivo_al_ingerir": motivo,
                             "inferencia_hoy": inferencia(a, af_hoy)[0],
                             "nombres_al_ingerir": json.dumps(sorted(set(map(tuple, afect_ing[cve]))),
                                                              ensure_ascii=False)[:300]})

    SALIDA.mkdir(parents=True, exist_ok=True)
    with (SALIDA / "perdidas_diagnostico.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(perdidas[0].keys()))
        w.writeheader()
        w.writerows(perdidas)
    with (SALIDA / "cambios_inferencia.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cve_id", "hostname", "cambio"])
        w.writerows(detalle_cambios)
    with (SALIDA / "resumen.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["medida", "valor"])
        w.writerows(sorted(cambios.items()))

    print(f"\nConsulta de hoy: {meta['consulta_utc']} | {meta['recibidos']} vulnerabilidades")
    print("\n(a) Inferencia al ingerir contra hoy (pares vulnerabilidad-activo):")
    for k, v in sorted(cambios.items()):
        print(f"  {k}: {v}")
    cves_perdidas = {p["cve_id"] for p in perdidas}
    print(f"\n(b) Nunca detectadas con coincidencia formal al 30/09: {len(cves_perdidas)} vulnerabilidades, "
          f"{len(perdidas)} pares")
    for k, v in Counter(p["motivo_al_ingerir"] for p in perdidas).most_common():
        print(f"  motivo al ingerir -- {k}: {v} pares")
    print(f"  la inferencia de hoy las encontraria: {sum(p['inferencia_hoy'] for p in perdidas)} pares")


if __name__ == "__main__":
    sys.exit(main())
