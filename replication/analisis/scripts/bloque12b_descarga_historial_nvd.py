"""Bloque 12B -- Descarga del historial de cambios de la NVD (seccion 5.4).

El bloque 12B (scripts/bloque12b_latencia_deteccion.py) solo pudo acotar cuando la NVD publico
la configuracion de las vulnerabilidades cuyo dato llego despues de la ventana de tres dias: una
cota inferior (la ultima corrida que las vio sin dato) y una superior (la ultima modificacion que
declaraba la NVD el 3/10). Este script descarga, para cada una de esas vulnerabilidades y para las
que recibieron el dato dentro de la ventana, el historial de cambios que publica la propia NVD
(API CVE Change History 2.0), donde cada evento trae su fecha. El analisis del historial esta en
scripts/bloque12b_fecha_configuracion.py.

La clave de la API se lee de la variable de entorno NVD_API_KEY y se envia en la cabecera
`apiKey`; no se escribe en ningun archivo. Entre peticiones se espera al menos un segundo y, ante
HTTP 403/429/503 o errores de conexion, se reintenta con esperas de 10, 30 y 60 segundos (la NVD
tiene una capa de mitigacion de bots que corta el trafico sostenido aun por debajo del limite
publicado). Es reanudable: no vuelve a consultar las vulnerabilidades cuyo archivo ya existe.

Uso: python scripts/bloque12b_descarga_historial_nvd.py [limite]
  limite: cantidad maxima de vulnerabilidades a consultar (para pruebas); sin argumento, todas.

Entradas: data/cleaned/bloque12b_latencia_deteccion/por_vulnerabilidad.csv (filas con
momento_del_dato = dentro_de_la_ventana o despues_de_la_ventana).
Salidas: data/raw/nvd_historial/<CVE>.json (respuesta cruda de la API, una por vulnerabilidad).
"""
import csv
import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ENTRADA = RAIZ / "data" / "cleaned" / "bloque12b_latencia_deteccion" / "por_vulnerabilidad.csv"
SALIDA = RAIZ / "data" / "raw" / "nvd_historial"
URL = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0?cveId={}"
GRUPOS = ("dentro_de_la_ventana", "despues_de_la_ventana")
PAUSA = 1.2
ESPERAS = (10, 30, 60)
REINTENTABLES = (403, 429, 503)


def pedir(cve, clave):
    peticion = urllib.request.Request(URL.format(cve), headers={"apiKey": clave})
    for intento, espera in enumerate((*ESPERAS, None)):
        try:
            with urllib.request.urlopen(peticion, timeout=60) as r:
                return r.read()
        except urllib.error.HTTPError as e:
            if e.code not in REINTENTABLES or espera is None:
                raise
            motivo = f"HTTP {e.code}"
        except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
            if espera is None:
                raise
            motivo = type(e).__name__
        print(f"  {cve}: {motivo}, reintento {intento + 1} en {espera} s", flush=True)
        time.sleep(espera)


def main():
    clave = os.environ["NVD_API_KEY"]
    limite = int(sys.argv[1]) if len(sys.argv) > 1 else None
    with ENTRADA.open(encoding="utf-8") as f:
        filas = [r for r in csv.DictReader(f) if r["momento_del_dato"] in GRUPOS]
    if limite is not None:
        # Mezcla de ambos grupos para la prueba.
        mitad = (limite + 1) // 2
        filas = ([r for r in filas if r["momento_del_dato"] == GRUPOS[0]][:mitad]
                 + [r for r in filas if r["momento_del_dato"] == GRUPOS[1]][:limite - mitad])
    SALIDA.mkdir(parents=True, exist_ok=True)
    pendientes = [r["cve_id"] for r in filas if not (SALIDA / f"{r['cve_id']}.json").exists()]
    print(f"{len(filas)} vulnerabilidades, {len(pendientes)} pendientes", flush=True)
    for i, cve in enumerate(pendientes, 1):
        cuerpo = pedir(cve, clave)
        json.loads(cuerpo)  # valida que la respuesta sea JSON antes de guardarla
        (SALIDA / f"{cve}.json").write_bytes(cuerpo)
        if i % 50 == 0:
            print(f"{i}/{len(pendientes)}", flush=True)
        time.sleep(PAUSA)
    print("listo", flush=True)


if __name__ == "__main__":
    main()
