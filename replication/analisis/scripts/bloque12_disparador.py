"""Bloque 12 -- Prueba del disparador por probabilidad de explotacion (apartado 5.3.5).

Regla probada: toda vulnerabilidad con probabilidad de explotacion de 0,04 o mas se notifica,
ademas de las que ya notifica el indice (>= 0,40). El 0,04 es el valor de referencia de FIRST
(percentil 90 aproximado; ver apartado 5.3.3). Se aplica sin datos nuevos, sobre tres fuentes
ya guardadas en la base:
  1. el valor registrado al detectar (telemetria_vulnerabilidades.epss_score);
  2. el valor de cierre de la reevaluacion diferida del 1 de octubre (epss_score_final);
  3. la serie diaria de FIRST capturada para las mismas vulnerabilidades (epss_serie_diaria),
     para ver si alguna cruzo 0,04 en un dia intermedio y volvio a bajar.

Agregado (12/10, apartado 5.3.6): con la serie diaria se recalcula, dia por dia, el indice de cada
par cambiando solo la probabilidad de explotacion (los demas componentes quedan con su valor al
detectar) y se registra el primer dia en que cada par habria cambiado de prioridad. La severidad
no tiene serie diaria; su cambio se mide en el apartado 5.3.2.

Unidad: vulnerabilidades distintas y pares vulnerabilidad-activo (3.883 pares del contraste).

Entradas: base de datos (solo lectura).
Salidas (data/cleaned/bloque12_disparador/): resumen.csv, cruces_serie_diaria.csv
"""
import csv
import io
import subprocess
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "data" / "cleaned" / "bloque12_disparador"
CONTENEDOR = "postgres_db"
UMBRAL_EPSS = 0.04
UMBRAL_INDICE = 0.40


def consulta(sql):
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -c "COPY ({sql}) TO STDOUT WITH CSV HEADER"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return list(csv.DictReader(io.StringIO(texto)))


def main():
    pares = consulta("select cve_id, activo_id, epss_score, epss_score_final, irc_score, prioridad, "
                     "(fecha_ingesta_pipeline - interval '3 hours')::date as dia_deteccion "
                     "from telemetria_vulnerabilidades")
    serie = consulta("select cve_id, fecha, epss_score from epss_serie_diaria order by cve_id, fecha")
    res = []

    def reg(medida, unidad, valor):
        res.append((medida, unidad, valor))

    reg("pares del contraste", "pares", len(pares))
    reg("vulnerabilidades del contraste", "vulnerabilidades", len({p["cve_id"] for p in pares}))
    reg("pares notificados por el indice", "pares", sum(float(p["irc_score"]) >= UMBRAL_INDICE for p in pares))
    for momento, col in (("al detectar", "epss_score"), ("al cierre", "epss_score_final")):
        disparan = [p for p in pares if float(p[col]) >= UMBRAL_EPSS]
        nuevos = [p for p in disparan if float(p["irc_score"]) < UMBRAL_INDICE]
        reg(f"{momento}: vulnerabilidades con probabilidad >= 0,04", "vulnerabilidades", len({p["cve_id"] for p in disparan}))
        reg(f"{momento}: pares que dispararia la regla", "pares", len(disparan))
        reg(f"{momento}: pares que dispararia y el indice no notifico", "pares", len(nuevos))

    # serie diaria: primer dia en que cada vulnerabilidad cruzo 0,04
    deteccion = {}
    for p in pares:
        deteccion.setdefault(p["cve_id"], p["dia_deteccion"])
    cruces = {}
    for s in serie:
        if s["epss_score"] and float(s["epss_score"]) >= UMBRAL_EPSS:
            c = cruces.setdefault(s["cve_id"], {"cve_id": s["cve_id"], "dia_deteccion": deteccion.get(s["cve_id"], ""),
                                                "primer_dia_sobre_0_04": s["fecha"], "dias_sobre_0_04": 0,
                                                "maximo": 0.0})
            c["dias_sobre_0_04"] += 1
            c["maximo"] = max(c["maximo"], float(s["epss_score"]))
    reg("serie diaria: vulnerabilidades con serie", "vulnerabilidades", len({s["cve_id"] for s in serie}))

    # escaladas por la probabilidad de explotacion, dia por dia (solo cambia ese componente)
    por_cve = {}
    for s_ in serie:
        if s_["epss_score"]:
            por_cve.setdefault(s_["cve_id"], []).append((s_["fecha"], float(s_["epss_score"])))
    escaladas = []
    for p in pares:
        resto = float(p["irc_score"]) - 0.25 * float(p["epss_score"])
        for fecha, e in por_cve.get(p["cve_id"], []):
            if fecha <= p["dia_deteccion"]:
                continue
            irc = resto + 0.25 * e
            prio = "CRITICA" if irc >= 0.70 else "ALTA" if irc >= UMBRAL_INDICE else "INFORMATIVA"
            if prio != p["prioridad"]:
                escaladas.append({"cve_id": p["cve_id"], "activo_id": p["activo_id"], "dia_deteccion": p["dia_deteccion"],
                                  "prioridad_al_detectar": p["prioridad"], "primer_dia_de_cambio": fecha,
                                  "prioridad_nueva": prio, "indice_ese_dia": round(irc, 4),
                                  "probabilidad_ese_dia": e})
                break
    reg("serie diaria: pares que habrian cambiado de prioridad algun dia posterior a la deteccion", "pares", len(escaladas))
    reg("serie diaria: vulnerabilidades que cruzaron 0,04 algun dia", "vulnerabilidades", len(cruces))

    SALIDA.mkdir(parents=True, exist_ok=True)
    with open(SALIDA / "cruces_serie_diaria.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["cve_id", "dia_deteccion", "primer_dia_sobre_0_04", "dias_sobre_0_04", "maximo"])
        w.writeheader()
        w.writerows(cruces.values())
    with open(SALIDA / "escaladas_serie_diaria.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["cve_id", "activo_id", "dia_deteccion", "prioridad_al_detectar",
                                           "primer_dia_de_cambio", "prioridad_nueva", "indice_ese_dia", "probabilidad_ese_dia"])
        w.writeheader()
        w.writerows(escaladas)
    with open(SALIDA / "resumen.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["medida", "unidad", "valor"])
        w.writerows(res)
    for m, u, v in res:
        print(f"{str(v):>6}  {m}  [{u}]")
    for c in cruces.values():
        print(c)
    for e in escaladas:
        print(e)


if __name__ == "__main__":
    main()
