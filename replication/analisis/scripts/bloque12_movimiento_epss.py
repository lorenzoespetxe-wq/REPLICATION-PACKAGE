"""Bloque 12 -- Cifras de los apartados 5.3.1, 5.3.3 y 5.3.6 que no salen de bloque2 ni de bloque8.

  1. Probabilidad de explotacion por vulnerabilidad (unidad: vulnerabilidad; el valor es el mismo
     en todos sus pares, se comprueba): sin dato al detectar (cero) y con dato al cierre; con dato
     en los dos momentos, sube / baja / no cambia; medianas; suben mas de 0,01; llegan a 0,04.
  2. Vulnerabilidades del catalogo de explotadas: fecha de ingreso, publicacion, deteccion y
     probabilidad al detectar y al cierre.
  3. Pares cuyo indice sube mas de 0,05: cuantos por severidad ausente al ingerir y cuantos no.
  4. Cambio medio del indice en los pares ingeridos sin severidad.
  5. El par de GitLab (CVE-2026-85706): valores guardados al detectar y al cierre.

Entradas: base de datos (solo lectura).
Salida: data/cleaned/bloque12_movimiento_epss/resumen.csv
"""
import csv
import io
import statistics
import subprocess
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "data" / "cleaned" / "bloque12_movimiento_epss"
CONTENEDOR = "postgres_db"
GITLAB = "CVE-2026-85706"


def consulta(sql):
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -c "COPY ({sql}) TO STDOUT WITH CSV HEADER"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return list(csv.DictReader(io.StringIO(texto)))


def main():
    filas = consulta("select cve_id, cvss_score, epss_score, epss_score_final, irc_score, irc_score_final, kev_status, "
                     "kev_fecha_agregado, fecha_publicacion_nvd, fecha_ingesta_pipeline, prioridad "
                     "from telemetria_vulnerabilidades")
    res = []

    def reg(medida, unidad, valor):
        res.append((medida, unidad, valor))

    # 1. probabilidad de explotacion por vulnerabilidad
    por_cve = {}
    for f in filas:
        par = (float(f["epss_score"]), float(f["epss_score_final"]))
        assert por_cve.setdefault(f["cve_id"], par) == par, f["cve_id"]
    e0 = {c: v[0] for c, v in por_cve.items()}
    e1 = {c: v[1] for c, v in por_cve.items()}
    llegan = [c for c in por_cve if e0[c] == 0]
    con_dato = [c for c in por_cve if e0[c] > 0]
    reg("vulnerabilidades", "vulnerabilidades", len(por_cve))
    reg("probabilidad: sin dato al detectar, con dato al cierre", "vulnerabilidades", sum(1 for c in llegan if e1[c] > 0))
    reg("probabilidad: sin dato al detectar, mediana al cierre", "probabilidad", statistics.median(e1[c] for c in llegan))
    reg("probabilidad: con dato, sube", "vulnerabilidades", sum(1 for c in con_dato if e1[c] > e0[c]))
    reg("probabilidad: con dato, baja", "vulnerabilidades", sum(1 for c in con_dato if e1[c] < e0[c]))
    reg("probabilidad: con dato, no cambia", "vulnerabilidades", sum(1 for c in con_dato if e1[c] == e0[c]))
    reg("probabilidad: sube contando las dos maneras", "vulnerabilidades", sum(1 for c in por_cve if e1[c] > e0[c]))
    reg("probabilidad: mediana al detectar (todas)", "probabilidad", statistics.median(e0.values()))
    reg("probabilidad: mediana al cierre (todas)", "probabilidad", statistics.median(e1.values()))
    reg("probabilidad: suben mas de 0,01", "vulnerabilidades", sum(1 for c in por_cve if e1[c] - e0[c] > 0.01))
    reg("probabilidad: 0,04 o mas al cierre", "vulnerabilidades", sum(1 for c in por_cve if e1[c] >= 0.04))

    # 2. catalogo de explotadas
    kev = {}
    for f in filas:
        if f["kev_status"] == "t":
            k = kev.setdefault(f["cve_id"], {"pares": 0, "ingreso_catalogo": f["kev_fecha_agregado"],
                                             "publicacion": f["fecha_publicacion_nvd"], "deteccion": f["fecha_ingesta_pipeline"],
                                             "prob_detectar": f["epss_score"], "prob_cierre": f["epss_score_final"]})
            k["pares"] += 1
    reg("catalogo de explotadas: vulnerabilidades", "vulnerabilidades", len(kev))
    for c, k in sorted(kev.items()):
        for campo, valor in k.items():
            reg(f"catalogo {c}: {campo}", "", valor)

    # 3 y 4. subidas del indice
    grandes = [f for f in filas if float(f["irc_score_final"]) - float(f["irc_score"]) > 0.05]
    reg("indice sube mas de 0,05", "pares", len(grandes))
    reg("  de ellos, ingeridos sin severidad", "pares", sum(1 for f in grandes if float(f["cvss_score"]) == 0))
    reg("  de ellos, con severidad al ingerir", "pares", sum(1 for f in grandes if float(f["cvss_score"]) > 0))
    sin_sev = [float(f["irc_score_final"]) - float(f["irc_score"]) for f in filas if float(f["cvss_score"]) == 0]
    reg("ingeridos sin severidad: cambio medio del indice", "indice", round(statistics.mean(sin_sev), 4))

    # 5. GitLab
    g = next(f for f in filas if f["cve_id"] == GITLAB)
    for campo in ("fecha_publicacion_nvd", "fecha_ingesta_pipeline", "epss_score", "epss_score_final",
                  "irc_score", "irc_score_final", "prioridad"):
        reg(f"{GITLAB}: {campo}", "", g[campo])

    SALIDA.mkdir(parents=True, exist_ok=True)
    with open(SALIDA / "resumen.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["medida", "unidad", "valor"])
        w.writerows(res)
    for m, u, v in res:
        print(f"{str(v):>26}  {m}  [{u}]")


if __name__ == "__main__":
    main()
