"""Devolucion del tribunal, observacion 5 -- Las 49 vulnerabilidades sin configuracion al 03/10.

Consulta el historial de cambios de la NVD para esas 49, de modo de establecer si alguna recibio
configuracion despues del cierre del 03/10 y cuando. Es reanudable y no necesita clave: entre
peticiones espera lo que exige el limite publicado para consultas sin clave.

Entrada: data/cleaned/devolucion_supervivencia_nvd/censuradas.csv
Salida:  data/raw/nvd_historial_censuradas/<CVE>.json,
         data/cleaned/devolucion_supervivencia_nvd/censuradas_despues_del_cierre.csv
"""
import csv
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ENTRADA = RAIZ / "data" / "cleaned" / "devolucion_supervivencia_nvd" / "censuradas.csv"
CRUDO = RAIZ / "data" / "raw" / "nvd_historial_censuradas"
SALIDA = RAIZ / "data" / "cleaned" / "devolucion_supervivencia_nvd" / "censuradas_despues_del_cierre.csv"
URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId={}"
PAUSA = 6.5
ESPERAS = (30, 60, 120)
TIPO = "CPE Configuration"


def pedir(cve):
    peticion = urllib.request.Request(URL.format(cve), headers={"User-Agent": "PoC_Tesis_SecOps/1.0"})
    for espera in (*ESPERAS, None):
        try:
            with urllib.request.urlopen(peticion, timeout=60) as r:
                return r.read()
        except (urllib.error.URLError, TimeoutError, ConnectionError):
            if espera is None:
                raise
            time.sleep(espera)


def main():
    CRUDO.mkdir(parents=True, exist_ok=True)
    with ENTRADA.open(encoding="utf-8", newline="") as f:
        cves = [r["cve_id"] for r in csv.DictReader(f)]
    assert len(cves) == 49, len(cves)
    filas = []
    for cve in cves:
        ruta = CRUDO / f"{cve}.json"
        if not ruta.exists():
            ruta.write_bytes(pedir(cve))
            time.sleep(PAUSA)
        eventos = json.loads(ruta.read_text(encoding="utf-8")).get("cveChanges", [])
        altas = [c["change"]["created"] for c in eventos
                 if any(d.get("type") == TIPO and d.get("action") == "Added" for d in c["change"].get("details", []))]
        filas.append({"cve_id": cve, "primera_configuracion_utc": min(altas) if altas else ""})
    with SALIDA.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["cve_id", "primera_configuracion_utc"])
        w.writeheader()
        w.writerows(filas)
    print("con configuracion posterior:", sum(bool(x["primera_configuracion_utc"]) for x in filas), "de", len(filas))


if __name__ == "__main__":
    main()
