"""Bloque 2 -- Movimiento del indice entre la deteccion y el cierre (segunda hipotesis).

Contrasta, para cada par vulnerabilidad-activo persistido, el valor registrado al detectar (columnas
originales) con el recalculado con informacion madura (columnas `_final`, escritas por el flujo de
reevaluacion diferida el 1 de octubre de 2026 sobre las 3.883 filas). Tambien compara esa
reevaluacion contra la anterior, del 10 de septiembre, conservada en el respaldo
`data/raw/respaldo_reevaluacion_antes_20261001.csv`, para las 3.283 filas que ya la tenian.

Unidad de computo: pares vulnerabilidad-activo, salvo donde se indica.
Umbrales de prioridad del flujo congelado: >= 0,70 CRITICA; >= 0,40 ALTA (se notifica); resto INFORMATIVA.

Entradas: base de datos (solo lectura) y el respaldo del 10/09.
Salidas (data/cleaned/bloque2_madurez/): resumen_movimiento.csv, transiciones_prioridad.csv
"""
import csv
import io
import statistics
import subprocess
from collections import Counter
from datetime import datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
RESPALDO = RAIZ / "data" / "raw" / "respaldo_reevaluacion_antes_20261001.csv"
SALIDA = RAIZ / "data" / "cleaned" / "bloque2_madurez"
CONTENEDOR = "postgres_db"
TOL = 0.00005  # medio paso de la precision de cuatro decimales con que la base guarda el indice


def prioridad(irc):
    return "CRITICA" if irc >= 0.70 else "ALTA" if irc >= 0.40 else "INFORMATIVA"


def leer_base():
    sql = ("COPY (select id, cve_id, activo_id, cvss_score, epss_score, kev_status, irc_score, prioridad, "
           "cvss_score_final, epss_score_final, kev_status_final, irc_score_final, "
           "fecha_publicacion_nvd, fecha_actualizacion_datos from telemetria_vulnerabilidades order by id) "
           "TO STDOUT WITH CSV HEADER")
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c", f'psql -U "$POSTGRES_USER" -d secops_research_db -c "{sql}"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return list(csv.DictReader(io.StringIO(texto)))


def f(x):
    return float(x) if x not in ("", None) else None


def main():
    filas = leer_base()
    previo = {r["id"]: r for r in csv.DictReader(open(RESPALDO, encoding="utf-8"))}
    res = []

    def reg(medida, unidad, valor):
        res.append((medida, unidad, valor))

    reg("pares", "pares", len(filas))
    reg("vulnerabilidades distintas", "vulnerabilidades", len({r["cve_id"] for r in filas}))

    # edad de la informacion al recalcular (dias entre publicacion y recalculo)
    edades = [(datetime.fromisoformat(r["fecha_actualizacion_datos"]) - datetime.fromisoformat(r["fecha_publicacion_nvd"])).days
              for r in filas]
    reg("edad al recalcular: minima", "dias", min(edades))
    reg("edad al recalcular: mediana", "dias", statistics.median(edades))
    reg("edad al recalcular: maxima", "dias", max(edades))

    # EPSS
    e0 = [f(r["epss_score"]) for r in filas]
    e1 = [f(r["epss_score_final"]) for r in filas]
    cambia_e = [i for i in range(len(filas)) if abs(e1[i] - e0[i]) > TOL]
    reg("EPSS: pares donde el valor de cierre difiere del de deteccion", "pares", len(cambia_e))
    reg("  de ellos, con EPSS = 0 al detectar (dato ausente)", "pares", sum(1 for i in cambia_e if e0[i] == 0))
    reg("EPSS: maximo al detectar", "probabilidad", max(e0))
    reg("EPSS: maximo al cierre", "probabilidad", max(e1))

    # KEV y severidad
    reg("KEV: pares que pasan de falso a verdadero", "pares",
        sum(1 for r in filas if r["kev_status"] == "f" and r["kev_status_final"] == "t"))
    reg("KEV: pares que pasan de verdadero a falso", "pares",
        sum(1 for r in filas if r["kev_status"] == "t" and r["kev_status_final"] == "f"))
    reg("KEV: pares verdaderos al cierre", "pares", sum(1 for r in filas if r["kev_status_final"] == "t"))
    c0 = [f(r["cvss_score"]) for r in filas]
    c1 = [f(r["cvss_score_final"]) for r in filas]
    reg("severidad (CVSS): pares con valor distinto al cierre", "pares", sum(1 for a, b in zip(c0, c1) if abs(a - b) > 0.0001))

    # pares sin puntaje de severidad al detectar (el flujo los trata como 0): a que banda pasan
    def banda(x):
        return "critica (9,0-10)" if x >= 9 else "alta (7,0-8,9)" if x >= 7 else "media (4,0-6,9)" if x >= 4 else "baja (0,1-3,9)"

    sin_puntaje = [(r, f(r["cvss_score_final"])) for r in filas if f(r["cvss_score"]) == 0]
    for nombre in ("baja (0,1-3,9)", "media (4,0-6,9)", "alta (7,0-8,9)", "critica (9,0-10)"):
        sel = [r for r, c in sin_puntaje if c > 0 and banda(c) == nombre]
        reg(f"sin puntaje al detectar, severidad al cierre {nombre}", "pares", len(sel))
    reg("sin puntaje al detectar y todavia sin puntaje al cierre", "pares", sum(1 for _, c in sin_puntaje if c == 0))
    reg("sin puntaje al detectar: indice mas alto al cierre", "indice",
        max(f(r["irc_score_final"]) for r, c in sin_puntaje))
    reg("sin puntaje al detectar: pares que cruzan el umbral de notificacion (0,40)", "pares",
        sum(1 for r, c in sin_puntaje if f(r["irc_score_final"]) >= 0.40))

    # indice
    i0 = [f(r["irc_score"]) for r in filas]
    i1 = [f(r["irc_score_final"]) for r in filas]
    d = [b - a for a, b in zip(i0, i1)]
    for umbral in (TOL, 0.005, 0.01, 0.05):
        reg(f"indice: pares con |cambio| > {umbral}", "pares", sum(1 for x in d if abs(x) > umbral))
    reg("indice: cambio maximo (valor absoluto)", "indice", max(abs(x) for x in d))
    reg("indice: cambio medio", "indice", round(statistics.mean(d), 5))

    # decision de prioridad y de notificar
    trans = Counter((r["prioridad"], prioridad(b)) for r, b in zip(filas, i1))
    reg("prioridad: pares que cambian de categoria", "pares", sum(v for (a, b), v in trans.items() if a != b))
    ant = sum(1 for a in i0 if a >= 0.40)
    post = sum(1 for b in i1 if b >= 0.40)
    reg("notificarian al detectar (indice >= 0,40)", "pares", ant)
    reg("notificarian con informacion madura (indice >= 0,40)", "pares", post)
    reg("  la decision cambia en", "pares", sum(1 for a, b in zip(i0, i1) if (a >= 0.40) != (b >= 0.40)))

    # reevaluacion del 10/09 contra la del 1/10
    comun = [(previo[r["id"]], r) for r in filas if previo[r["id"]]["irc_score_final"]]
    reg("filas con reevaluacion del 10/09", "pares", len(comun))
    reg("  indice de cierre distinto entre la del 10/09 y la del 01/10", "pares",
        sum(1 for p, r in comun if abs(f(p["irc_score_final"]) - f(r["irc_score_final"])) > TOL))
    reg("  EPSS de cierre distinto entre la del 10/09 y la del 01/10", "pares",
        sum(1 for p, r in comun if abs(f(p["epss_score_final"]) - f(r["epss_score_final"])) > TOL))
    reg("  KEV de cierre distinto entre la del 10/09 y la del 01/10", "pares",
        sum(1 for p, r in comun if p["kev_status_final"] != r["kev_status_final"]))

    SALIDA.mkdir(parents=True, exist_ok=True)
    with open(SALIDA / "resumen_movimiento.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["medida", "unidad", "valor"])
        w.writerows(res)
    with open(SALIDA / "transiciones_prioridad.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["prioridad_al_detectar", "prioridad_con_informacion_madura", "pares"])
        w.writerows([[a, b, v] for (a, b), v in sorted(trans.items())])

    for m, u, v in res:
        print(f"{str(v):>9}  {m}  [{u}]")
    print("transiciones:", dict(trans))


if __name__ == "__main__":
    main()
