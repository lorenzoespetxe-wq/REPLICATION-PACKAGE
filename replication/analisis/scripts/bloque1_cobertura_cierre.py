"""Bloque 1 -- Cobertura formal al cierre, vulnerabilidades retiradas y contraste con la deteccion.

Entradas (todas ya descargadas; este script no consulta ni la NVD ni la base):
  data/raw/corridas_campana.csv        las 28 filas de auditoria de la campana (con `ids`)
  data/raw/activos_inventario.csv      los 30 activos y su identificador de plataforma
  data/raw/nvd_reconsulta/cves_*.csv   reconsulta de cierre (scripts/bloque1_reconsulta_nvd.py)
  data/raw/nvd_reconsulta/meta_*.json  instante exacto de la reconsulta

La regla de coincidencia formal replica la del nodo `Parse NVD Response` del flujo: un activo
coincide con un CVE si alguna de las dos claves del activo (fabricante+producto, y
fabricante+producto+version) figura entre las claves de los identificadores de plataforma
del bloque de configuraciones del CVE. La version no se compara en la primera clave.

Salidas en data/cleaned/bloque1_cobertura_cierre/ (sin titulos ni notas; los pone el documento).
"""
import csv
import json
import re
from datetime import date, datetime, timedelta
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
RAW = RAIZ / "data" / "raw"
SALIDA = RAIZ / "data" / "cleaned" / "bloque1_cobertura_cierre"
TRAMOS = [(0, 7), (8, 14), (15, 21), (22, 99)]


# ---------- regla de coincidencia del flujo ----------

def palabras(*campos):
    tokens = re.split(r"[_\-.\s]+", "_".join(campos).lower())
    return "|".join(sorted(t for t in tokens if t and t != "*"))


def claves_cpe(cpe):
    p = cpe.split(":")
    if len(p) < 5 or p[1] != "2.3":
        return []
    vendor, product = p[3], p[4]
    version = p[5] if len(p) > 5 else "*"
    return [palabras(vendor, product), palabras(vendor, product, version)]


# ---------- carga ----------

def leer_csv(ruta):
    with ruta.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def cargar():
    corridas = leer_csv(RAW / "corridas_campana.csv")
    activos = {int(a["activo_id"]): claves_cpe(a["cpe"]) for a in leer_csv(RAW / "activos_inventario.csv")}
    ruta_cves = sorted((RAW / "nvd_reconsulta").glob("cves_2*.csv"))[-1]
    meta = json.loads(sorted((RAW / "nvd_reconsulta").glob("meta_2*.json"))[-1].read_text(encoding="utf-8"))
    cves = leer_csv(ruta_cves)
    return corridas, activos, cves, meta


def activos_que_coinciden(cpes, activos):
    claves = {k for c in cpes.split() for k in claves_cpe(c)}
    return [aid for aid, ks in activos.items() if any(k in claves for k in ks)]


def ventana(dia_local):
    d = date.fromisoformat(dia_local)
    return f"{(d - timedelta(days=2)).isoformat()}T00:00:00.000", f"{d.isoformat()}T23:59:59.999"


def main():
    corridas, activos, cves, meta = cargar()
    consulta = datetime.fromisoformat(meta["consulta_utc"]).replace(tzinfo=None)

    # Estado de cada CVE hoy: retirado, con configuraciones, activos que coinciden, edad.
    estado = {}
    for c in cves:
        coin = activos_que_coinciden(c["cpes"], activos) if c["cpes"] else []
        edad = (consulta - datetime.fromisoformat(c["published"])).days
        estado[c["cve_id"]] = {"pub": c["published"], "status": c["vuln_status"],
                               "retirado": c["vuln_status"] == "Rejected",
                               "con_config": int(c["n_configs"]) > 0,
                               "activos": coin, "edad": edad}

    # ---- por corrida ----
    filas, incoherencias = [], 0
    for r in corridas:
        ini, fin = ventana(r["dia_local"])
        universo = [k for k, v in estado.items() if ini <= v["pub"] <= fin]
        # Lo que la NVD ya habia publicado cuando corrio el flujo: comparacion justa con lo ingerido.
        visible = [k for k in universo if estado[k]["pub"] <= r["ts_utc"]]
        det = set(r["ids"].split()) if r["ids"] else set()
        formal_hoy = {k for k in universo if estado[k]["activos"]}
        n1 = int(r["n1_formal_nvd"])
        inter = formal_hoy & det
        if len(inter) < n1:
            incoherencias += 1
        filas.append({
            "fila_auditoria": r["fila_auditoria"], "dia_local": r["dia_local"],
            "ventana_ini": ini, "ventana_fin": fin,
            "ingeridos_deteccion": int(r["cve_ingeridos"]), "universo_hoy": len(universo),
            "universo_visible_a_la_hora": len(visible),
            "retiradas_hoy": sum(estado[k]["retirado"] for k in universo),
            "con_config_hoy": sum(estado[k]["con_config"] for k in universo),
            "correlacionados_deteccion": len(det), "n1_formal_deteccion": n1,
            "n4_inferencia_deteccion": int(r["n4_inferencia"]),
            "formal_hoy": len(formal_hoy),
            "formal_hoy_y_detectado": len(inter),
            "formal_hoy_no_detectado": len(formal_hoy - det),
            "detectado_sin_formal_hoy": len(det - formal_hoy),
            "detectado_ausente_en_universo": len(det - set(universo)),
        })

    # ---- por CVE distinto, sobre la union de ventanas, por tramo de edad ----
    tramos = []
    for lo, hi in TRAMOS:
        g = [v for v in estado.values() if lo <= v["edad"] <= hi]
        tramos.append({"edad_dias": f"{lo}-{hi}" if hi < 99 else f"{lo}+", "cves": len(g),
                       "retirados": sum(v["retirado"] for v in g),
                       "diferidos": sum(v["status"] == "Deferred" for v in g),
                       "con_config": sum(v["con_config"] for v in g),
                       "formal_sobre_activo": sum(bool(v["activos"]) for v in g)})
    total = {"edad_dias": "total", "cves": len(estado),
             "retirados": sum(v["retirado"] for v in estado.values()),
             "diferidos": sum(v["status"] == "Deferred" for v in estado.values()),
             "con_config": sum(v["con_config"] for v in estado.values()),
             "formal_sobre_activo": sum(bool(v["activos"]) for v in estado.values())}
    tramos.append(total)

    # ---- CVE distintos: formal hoy contra detectado en alguna corrida ----
    detectados = set()
    for r in corridas:
        detectados |= set(r["ids"].split())
    formal_hoy_total = {k for k, v in estado.items() if v["activos"]}
    nunca = formal_hoy_total - detectados
    sensibilidad = []  # misma tabla por edad, sin los tres dias del lote masivo de septiembre
    for lo, hi in TRAMOS:
        g = [v for v in estado.values() if lo <= v["edad"] <= hi
             and not ("2026-09-08" <= v["pub"][:10] <= "2026-09-10")]
        sensibilidad.append({"edad_dias": f"{lo}-{hi}" if hi < 99 else f"{lo}+", "cves": len(g),
                             "con_config": sum(v["con_config"] for v in g),
                             "formal_sobre_activo": sum(bool(v["activos"]) for v in g)})

    # ---- pares CVE-activo con coincidencia formal hoy (insumo del bloque 8) ----
    pares = [(k, a) for k, v in estado.items() for a in v["activos"]]

    SALIDA.mkdir(parents=True, exist_ok=True)
    for nombre, datos in (("por_corrida.csv", filas), ("por_tramo_de_edad.csv", tramos)):
        with (SALIDA / nombre).open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(datos[0]))
            w.writeheader()
            w.writerows(datos)
    with (SALIDA / "pares_formales_hoy.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["cve_id", "activo_id"])
        w.writerows(pares)

    print(f"Reconsulta del {meta['consulta_utc']} | CVE: {len(estado)} | pares formales hoy: {len(pares)}")
    print(f"Corridas donde formal_hoy&detectado < n1 (incoherencia): {incoherencias} de {len(filas)}")
    print(f"\nCVE DISTINTOS: detectados en alguna corrida={len(detectados)} | formal hoy sobre algun activo={len(formal_hoy_total)}"
          f" | formal hoy Y detectado={len(formal_hoy_total & detectados)} | formal hoy y NUNCA detectado={len(nunca)}")
    print("\nSENSIBILIDAD: por tramo de edad SIN publicados del 8 al 10 de septiembre")
    for t in sensibilidad:
        print(t)
    print("\nPOR TRAMO DE EDAD (CVE distintos)")
    for t in tramos:
        print(t)
    print("\nPOR CORRIDA")
    cols = ["fila_auditoria", "dia_local", "ingeridos_deteccion", "universo_hoy", "universo_visible_a_la_hora", "retiradas_hoy",
            "con_config_hoy", "correlacionados_deteccion", "n1_formal_deteccion", "formal_hoy",
            "formal_hoy_no_detectado", "detectado_sin_formal_hoy", "detectado_ausente_en_universo"]
    print(" | ".join(cols))
    for f_ in filas:
        print(" | ".join(str(f_[c]) for c in cols))


if __name__ == "__main__":
    main()
