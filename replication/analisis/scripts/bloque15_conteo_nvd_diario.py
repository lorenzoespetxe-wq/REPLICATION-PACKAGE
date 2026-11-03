"""Bloque 15 (apartado 7.1.4): cuántos registros modifica y publica la NVD por día.

Pide a la interfaz de la NVD un solo resultado por consulta y lee el total que
informa la respuesta. Sin clave: pausa de 7 s entre consultas para no activar el
bloqueo por volumen. El conteo de un día pasado puede bajar con el tiempo, porque
un registro que vuelve a modificarse sale de ese día.
"""
import csv
import datetime as dt
import json
import time
import urllib.request
from pathlib import Path

BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=1"
DIAS = [("2026-10-13", "2026-10-14"), ("2026-10-14", "2026-10-15")]
SALIDA = Path("data/raw/nvd_modificaciones_diarias/conteo_diario_20261015.csv")

filas = []
for inicio, fin in DIAS:
    for medida, desde, hasta in [("modificadas", "lastModStartDate", "lastModEndDate"),
                                 ("publicadas", "pubStartDate", "pubEndDate")]:
        url = f"{BASE}&{desde}={inicio}T00:00:00.000Z&{hasta}={fin}T00:00:00.000Z"
        pedido = urllib.request.Request(url, headers={"User-Agent": "PoC_Tesis_SecOps/1.0"})
        total = json.load(urllib.request.urlopen(pedido, timeout=40))["totalResults"]
        filas.append((inicio, medida, total))
        time.sleep(7)

consultado = dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")
SALIDA.parent.mkdir(parents=True, exist_ok=True)
with SALIDA.open("w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["dia_utc", "medida", "total_nvd", "consultado_utc"])
    w.writerows(fila + (consultado,) for fila in filas)
