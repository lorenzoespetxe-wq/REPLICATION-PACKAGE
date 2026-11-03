"""Bloque 2 -- Suelo del EPSS: que significa un EPSS igual a cero al momento de la deteccion.

La base guarda el EPSS con cuatro decimales (`NUMERIC(5,4)`) y el flujo escribe 0 cuando FIRST no
devolvio valor. Un cero puede ser entonces (a) un valor ausente: FIRST todavia no habia puntuado la
vulnerabilidad, o (b) un valor real por debajo de 0,00005 que el redondeo lleva a cero.

Para cada par persistido con EPSS igual a cero se consulta a FIRST (scope=time-series) la serie
historica de la vulnerabilidad y se registra la primera fecha con valor y el valor minimo de la
serie. Si la primera fecha es posterior a la de ingesta, el cero fue ausencia; si hubiera un valor
vigente a la fecha de ingesta menor a 0,00005, habria sido redondeo.

Entradas: base de datos (solo lectura) y API publica de FIRST.
Salida:   data/cleaned/bloque2_suelo_epss/ceros_epss.csv
"""
import csv
import json
import subprocess
import urllib.request
from datetime import date
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "data" / "cleaned" / "bloque2_suelo_epss"
CONTENEDOR = "postgres_db"
API_FIRST = "https://api.first.org/data/v1/epss?scope=time-series&cve="
PISO_REDONDEO = 0.00005  # menor valor que el redondeo a 4 decimales no lleva a cero


def psql(sql):
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -At -F "," -c "{sql}"']
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout


def main():
    sql = ("select cve_id, min(fecha_ingesta_pipeline)::date, min(fecha_publicacion_nvd)::date "
           "from telemetria_vulnerabilidades where epss_score = 0 group by 1 order by 1")
    ceros = [l.split(",") for l in psql(sql).strip().splitlines()]
    total_pares = int(psql("select count(*) from telemetria_vulnerabilidades where epss_score = 0").strip())

    serie = {}
    for i in range(0, len(ceros), 30):
        lote = [c[0] for c in ceros[i:i + 30]]
        with urllib.request.urlopen(API_FIRST + ",".join(lote), timeout=60) as r:
            for x in json.load(r)["data"]:
                serie[x["cve"]] = sorted((t["date"], float(t["epss"])) for t in x.get("time-series", []))

    SALIDA.mkdir(parents=True, exist_ok=True)
    resumen = {"sin_valor_en_first": 0, "primera_fecha_posterior_a_ingesta": 0,
               "valor_vigente_a_la_ingesta": 0, "valor_vigente_menor_al_piso": 0}
    minimo_global = None
    with open(SALIDA / "ceros_epss.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cve_id", "fecha_ingesta", "fecha_publicacion", "primera_fecha_first",
                    "dias_primera_menos_ingesta", "valor_minimo_serie", "valor_primera_fecha"])
        for cve, ing, pub in ceros:
            s = serie.get(cve, [])
            if not s:
                resumen["sin_valor_en_first"] += 1
                w.writerow([cve, ing, pub, "", "", "", ""])
                continue
            primera, valor = s[0]
            dias = (date.fromisoformat(primera) - date.fromisoformat(ing)).days
            if dias > 0:
                resumen["primera_fecha_posterior_a_ingesta"] += 1
            else:
                resumen["valor_vigente_a_la_ingesta"] += 1
                if valor < PISO_REDONDEO:
                    resumen["valor_vigente_menor_al_piso"] += 1
            minimo = min(v for _, v in s)
            minimo_global = minimo if minimo_global is None else min(minimo_global, minimo)
            w.writerow([cve, ing, pub, primera, dias, minimo, valor])

    print("pares con EPSS = 0 en la base:", total_pares, "| vulnerabilidades distintas:", len(ceros))
    for k, v in resumen.items():
        print(f"  {k}: {v}")
    print("valor minimo de EPSS en todas las series consultadas:", minimo_global)


if __name__ == "__main__":
    main()
