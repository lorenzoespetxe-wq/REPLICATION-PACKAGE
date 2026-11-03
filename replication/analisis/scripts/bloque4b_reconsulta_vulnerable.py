"""Bloque 4B -- Reconsulta a la NVD guardando la marca `vulnerable` de cada identificador.

La reconsulta del bloque 1 (scripts/bloque1_reconsulta_nvd.py) guardo todos los
identificadores de plataforma del bloque de configuraciones sin distinguir la marca
`vulnerable`, que es como lo prueba el nodo de correlacion del flujo. Esa marca separa el
producto afectado (`vulnerable=true`) de la plataforma sobre la que corre (`vulnerable=false`,
p. ej. Windows bajo una falla de Photoshop). Este script repite la consulta sobre el mismo
rango y guarda las dos listas por separado, para medir la cobertura con y sin las
coincidencias solo de plataforma sobre una misma foto de la fuente.

No escribe nada en la base ni toca el orquestador. Escribe en data/raw/nvd_reconsulta/ con
nombres que no coinciden con los patrones que leen los scripts del bloque 1.

Uso (desde la raiz del proyecto; la clave es opcional y solo acelera):
    python scripts/bloque4b_reconsulta_vulnerable.py --prueba     # 5 registros, sin guardar
    python scripts/bloque4b_reconsulta_vulnerable.py              # consulta completa
"""
import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bloque1_reconsulta_nvd import POR_PAGINA, pedir, rango_de_la_campana  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "data" / "raw" / "nvd_reconsulta"
COLUMNAS = ["cve_id", "published", "last_modified", "vuln_status", "n_configs",
            "cpes_vulnerables", "cpes_plataforma"]


def aplanar(vuln):
    """Separa los identificadores del bloque de configuraciones segun la marca `vulnerable`."""
    cve = vuln["cve"]
    configs = cve.get("configurations", [])
    marcas = [(m["criteria"], m.get("vulnerable", False)) for c in configs
              for nodo in c.get("nodes", []) for m in nodo.get("cpeMatch", []) if m.get("criteria")]
    return {"cve_id": cve["id"], "published": cve["published"],
            "last_modified": cve["lastModified"], "vuln_status": cve.get("vulnStatus", ""),
            "n_configs": len(configs),
            "cpes_vulnerables": " ".join(c for c, v in marcas if v),
            "cpes_plataforma": " ".join(c for c, v in marcas if not v)}


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

    sello = consulta_utc[:10].replace("-", "")
    with (SALIDA / f"configs_vulnerable_{sello}.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLUMNAS)
        w.writeheader()
        w.writerows(filas)
    meta = {"consulta_utc": consulta_utc, "pubStartDate": inicio, "pubEndDate": fin,
            "paginas": pagina, "recibidos": len(filas), "total_declarado_por_pagina": totales,
            "total_cambio_durante_el_recorrido": len(set(totales)) > 1,
            "con_clave": bool(clave)}
    (SALIDA / f"meta_configs_vulnerable_{sello}.json").write_text(json.dumps(meta, indent=1),
                                                                  encoding="utf-8")
    print(json.dumps(meta, indent=1))


if __name__ == "__main__":
    sys.exit(main())
