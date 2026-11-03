"""Bloque 12 -- Que componente del indice decidio cada notificacion (apartado 5.3.4).

Dos medidas, ambas con los pesos y el umbral congelados de la seccion 3.6:
  1. Para cada par notificado (indice al detectar >= 0,40), que componentes son necesarios: un
     componente es necesario cuando, al quitar su aporte, el indice queda por debajo de 0,40.
     Unidad: pares notificados (17).
  2. Para cada combinacion de criticidad y exposicion del inventario, la severidad minima que
     necesita una vulnerabilidad para notificar sin explotacion confirmada y con probabilidad de
     explotacion nula: (0,40 - aporte de criticidad - aporte de exposicion) / 0,15 * 10. Un valor
     mayor que 10 significa que ese activo no puede notificar por severidad. Unidad: activos (30).
  3. Aporte de cada componente al indice medio al detectar, sobre los 3.883 pares del contraste
     (campana y estabilizacion, seccion 3.3). Unidad: pares.

El indice se reconstruye desde los componentes guardados al detectar y se comprueba contra el
guardado (diferencia maxima admitida: 0,0001, la precision de la base).

Entradas: base de datos (solo lectura).
Salidas (data/cleaned/bloque12_componente_decisivo/): notificaciones_componentes.csv,
severidad_minima_por_activo.csv, resumen.csv
"""
import csv
import io
import subprocess
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "data" / "cleaned" / "bloque12_componente_decisivo"
CONTENEDOR = "postgres_db"
PESOS = {"severidad": 0.15, "probabilidad": 0.25, "explotacion": 0.30, "criticidad": 0.20, "exposicion": 0.10}
UMBRAL = 0.40
TOL = 0.0001


def consulta(sql):
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -c "COPY ({sql}) TO STDOUT WITH CSV HEADER"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return list(csv.DictReader(io.StringIO(texto)))


def aportes(f):
    return {"severidad": PESOS["severidad"] * float(f["cvss_score"]) / 10,
            "probabilidad": PESOS["probabilidad"] * float(f["epss_score"]),
            "explotacion": PESOS["explotacion"] * (f["kev_status"] == "t"),
            "criticidad": PESOS["criticidad"] * float(f["peso_normalizacion"]),
            "exposicion": PESOS["exposicion"] * (f["exposicion_internet"] == "t")}


def main():
    filas = consulta("select t.cve_id, a.hostname, t.cvss_score, t.epss_score, t.kev_status, t.irc_score, "
                     "c.peso_normalizacion, a.exposicion_internet from telemetria_vulnerabilidades t "
                     "join activos a on a.id = t.activo_id join criticidad_niveles c on c.id = a.criticidad_id")
    res = []

    def reg(medida, unidad, valor):
        res.append((medida, unidad, valor))

    # 1. componentes necesarios en cada notificacion
    notif, necesarios = [], Counter()
    sin_explotacion = 0
    for f in filas:
        ap = aportes(f)
        total = sum(ap.values())
        assert abs(total - float(f["irc_score"])) <= TOL, f
        if ap["explotacion"] == 0 and total >= UMBRAL:
            sin_explotacion += 1
        if float(f["irc_score"]) < UMBRAL:
            continue
        nec = [k for k, v in ap.items() if total - v < UMBRAL]
        necesarios.update(nec)
        notif.append({"cve_id": f["cve_id"], "activo": f["hostname"], "indice": round(total, 4),
                      **{f"aporte_{k}": round(v, 4) for k, v in ap.items()},
                      "componentes_necesarios": " + ".join(nec)})
    reg("pares notificados", "pares", len(notif))
    for k in PESOS:
        reg(f"notificaciones en que es necesario: {k}", "pares", necesarios[k])
    reg("notificaciones sin explotacion confirmada", "pares", sin_explotacion)
    reg("notificaciones con explotacion confirmada", "pares", len(notif) - sin_explotacion)
    reg("aporte maximo de la probabilidad de explotacion en un par notificado", "indice",
        round(max(n["aporte_probabilidad"] for n in notif), 4))

    # aporte de cada componente al indice medio, sobre todos los pares del contraste (3.883)
    suma = Counter()
    for f in filas:
        suma.update(aportes(f))
    total_medio = sum(suma.values()) / len(filas)
    reg("pares del contraste", "pares", len(filas))
    reg("indice medio al detectar", "indice", round(total_medio, 4))
    for k in PESOS:
        reg(f"aporte al indice medio: {k}", "porcentaje", round(100 * suma[k] / sum(suma.values()), 1))

    # 2. severidad minima para notificar sin explotacion confirmada ni probabilidad
    activos = consulta("select a.hostname, c.nombre as criticidad, c.peso_normalizacion, a.exposicion_internet "
                       "from activos a join criticidad_niveles c on c.id = a.criticidad_id order by a.hostname")
    tabla = []
    for a in activos:
        resto = UMBRAL - PESOS["criticidad"] * float(a["peso_normalizacion"]) - PESOS["exposicion"] * (a["exposicion_internet"] == "t")
        tabla.append({"activo": a["hostname"], "criticidad": a["criticidad"],
                      "expuesto_a_internet": a["exposicion_internet"] == "t",
                      "aporte_del_activo": round(UMBRAL - resto, 4), "falta_para_el_umbral": round(resto, 4),
                      "severidad_minima_sin_explotacion": round(resto / PESOS["severidad"] * 10, 2),
                      "severidad_minima_con_explotacion": round(max(0.0, resto - PESOS["explotacion"]) / PESOS["severidad"] * 10, 2)})
    reg("activos del inventario", "activos", len(tabla))
    reg("activos que pueden notificar por severidad sin explotacion (minimo < 10)", "activos",
        sum(1 for t in tabla if t["severidad_minima_sin_explotacion"] < 10))
    reg("activos que solo notifican sin explotacion con severidad 10,0 (minimo = 10)", "activos",
        sum(1 for t in tabla if t["severidad_minima_sin_explotacion"] == 10))
    reg("con explotacion confirmada: activos que notifican con cualquier severidad", "activos",
        sum(1 for t in tabla if t["severidad_minima_con_explotacion"] == 0))
    reg("con explotacion confirmada: severidad minima en los demas activos", "puntaje",
        max(t["severidad_minima_con_explotacion"] for t in tabla))
    reg("activos que no pueden notificar por severidad sin explotacion (minimo > 10)", "activos",
        sum(1 for t in tabla if t["severidad_minima_sin_explotacion"] > 10))

    SALIDA.mkdir(parents=True, exist_ok=True)
    with open(SALIDA / "notificaciones_componentes.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(notif[0]))
        w.writeheader()
        w.writerows(notif)
    with open(SALIDA / "severidad_minima_por_activo.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(tabla[0]))
        w.writeheader()
        w.writerows(tabla)
    with open(SALIDA / "resumen.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["medida", "unidad", "valor"])
        w.writerows(res)
    for m, u, v in res:
        print(f"{str(v):>7}  {m}  [{u}]")


if __name__ == "__main__":
    main()
