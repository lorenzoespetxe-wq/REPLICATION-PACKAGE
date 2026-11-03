"""Bloque 1 -- Reconsulta de cierre a la NVD.

Pide a la NVD, una sola vez, el rango completo que cubren las 28 ventanas de la
campana y guarda por cada vulnerabilidad lo necesario para medir despues, sin volver a
consultar: fecha de publicacion, estado, y si trae configuraciones (y de que fuente).

Por que un solo rango y no 28 consultas: cada ventana se reconstruye despues filtrando
por fecha de publicacion, con la misma regla del flujo (00:00 de dos dias antes de la
fecha local de la corrida hasta 23:59:59.999 de esa fecha, interpretadas como UTC).
Asi todas las ventanas se miran en el mismo instante y con el mismo estado de la fuente.

No escribe nada en la base ni toca el orquestador.

Uso (PowerShell, desde la raiz del proyecto):
    $env:NVD_API_KEY = "<clave>"      # solo en esa sesion; no se escribe en ningun archivo
    python scripts/bloque1_reconsulta_nvd.py --prueba     # 5 registros, sin guardar
    python scripts/bloque1_reconsulta_nvd.py              # consulta completa
"""
import argparse
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ENTRADA = RAIZ / "data" / "raw" / "corridas_campana.csv"
SALIDA = RAIZ / "data" / "raw" / "nvd_reconsulta"
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
POR_PAGINA = 2000
REINTENTOS = 6
COLUMNAS = ["cve_id", "published", "last_modified", "vuln_status",
            "n_configs", "config_sources", "cpes"]


def rango_de_la_campana():
    """Devuelve (inicio, fin) como cadenas en el formato que usa el flujo."""
    with ENTRADA.open(encoding="utf-8", newline="") as f:
        dias = [date.fromisoformat(fila["dia_local"]) for fila in csv.DictReader(f)]
    inicio = min(dias) - timedelta(days=2)
    fin = max(dias)
    return f"{inicio.isoformat()}T00:00:00.000", f"{fin.isoformat()}T23:59:59.999"


def pedir(params, clave):
    """Una peticion con reintentos ante limite de ritmo o caida momentanea."""
    url = f"{URL}?{urllib.parse.urlencode(params)}"
    cabeceras = {"User-Agent": "PoC_Tesis_SecOps/1.0 (reconsulta de cierre)",
                 "Accept": "application/json"}
    if clave:
        cabeceras["apiKey"] = clave
    for intento in range(1, REINTENTOS + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=cabeceras),
                                        timeout=120) as r:
                return json.load(r)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            codigo = getattr(e, "code", None)
            if codigo in (400, 401, 404):  # no se arregla reintentando
                raise SystemExit(f"Error {codigo} de la NVD: revisar parametros o clave.")
            espera = 10 * intento
            print(f"  intento {intento} fallo ({codigo or e}); espero {espera} s", flush=True)
            time.sleep(espera)
    raise SystemExit("La NVD no respondio tras los reintentos.")


def aplanar(vuln):
    """Reduce un registro de la NVD a las columnas de COLUMNAS.

    Guarda todos los identificadores de plataforma del bloque de configuraciones, sin
    filtrar por el indicador `vulnerable`: es lo que prueba el nodo de correlacion del flujo.
    """
    cve = vuln["cve"]
    configs = cve.get("configurations", [])
    cpes = [m["criteria"] for c in configs for nodo in c.get("nodes", [])
            for m in nodo.get("cpeMatch", []) if m.get("criteria")]
    return {"cve_id": cve["id"], "published": cve["published"],
            "last_modified": cve["lastModified"], "vuln_status": cve.get("vulnStatus", ""),
            "n_configs": len(configs),
            "config_sources": "|".join(sorted({c.get("source", "") for c in configs})),
            "cpes": " ".join(cpes)}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prueba", action="store_true", help="5 registros, sin guardar nada")
    args = ap.parse_args()

    clave = os.environ.get("NVD_API_KEY", "")
    pausa = 1 if clave else 7
    inicio, fin = rango_de_la_campana()
    print(f"Rango: {inicio} a {fin} | clave: {'si' if clave else 'NO (modo lento)'}")

    filas, totales, pagina = [], [], 0
    consulta_utc = datetime.now(timezone.utc).isoformat(timespec="seconds")
    por_pagina = 5 if args.prueba else POR_PAGINA
    while True:
        params = {"pubStartDate": inicio, "pubEndDate": fin,
                  "resultsPerPage": por_pagina, "startIndex": pagina * por_pagina}
        cuerpo = pedir(params, clave)
        totales.append(cuerpo["totalResults"])
        filas += [aplanar(v) for v in cuerpo["vulnerabilities"]]
        pagina += 1
        print(f"  pagina {pagina}: {len(filas)} de {cuerpo['totalResults']}", flush=True)
        if args.prueba or len(filas) >= cuerpo["totalResults"] or not cuerpo["vulnerabilities"]:
            break
        time.sleep(pausa)

    if args.prueba:
        print(json.dumps(filas[:2], indent=1, ensure_ascii=False)[:1500])
        return

    SALIDA.mkdir(parents=True, exist_ok=True)
    sello = consulta_utc[:10].replace("-", "")
    with (SALIDA / f"cves_{sello}.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNAS)
        w.writeheader()
        w.writerows(filas)
    meta = {"consulta_utc": consulta_utc, "pubStartDate": inicio, "pubEndDate": fin,
            "paginas": pagina, "recibidos": len(filas), "total_declarado_por_pagina": totales,
            "total_cambio_durante_el_recorrido": len(set(totales)) > 1,
            "con_clave": bool(clave)}
    (SALIDA / f"meta_{sello}.json").write_text(json.dumps(meta, indent=1), encoding="utf-8")
    print(json.dumps(meta, indent=1))


if __name__ == "__main__":
    sys.exit(main())
