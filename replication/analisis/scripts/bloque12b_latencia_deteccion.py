"""Bloque 12B -- Demora de la NVD y momento de la deteccion por via (seccion 5.4).

Complementa los tres intervalos del bloque 8 (scripts/bloque8_telemetria.py). Aquel midio la
demora de la NVD solo sobre los pares inferidos que el flujo vio confirmar dentro de la ventana
de tres dias; este script ubica a las 1.018 vulnerabilidades correlacionadas de la campana segun
cuando recibieron la configuracion de la NVD, que es el dato que usa la via formal:

  1. con dato en la primera corrida que las ingirio;
  2. el dato llego dentro de la ventana (alguna corrida posterior lo trajo);
  3. el dato llego despues de que salieran de la ventana (ninguna corrida lo vio; la consulta
     del 3/10 lo tiene). Para ellas solo hay cotas: la inferior es la ultima corrida que las vio
     sin dato; la superior, la fecha de ultima modificacion que declara la NVD el 3/10, que
     registra cualquier cambio y no solo el analisis (seccion 1.8);
  4. sin dato al 3/10.

"Dato" = la NVD publico al menos una configuracion para la vulnerabilidad (n_configs > 0),
coincida o no con el inventario.

Ademas, por via de deteccion: si la vulnerabilidad se detecto en la primera corrida posterior a
su publicacion o en una posterior (via formal que espero el dato).

Unidad: vulnerabilidades distintas. Universo: campana (ingesta desde el 30/08 00:00 locales).
Entradas: base (solo lectura); data/raw/estado_al_ingerir.csv (lo que la NVD devolvio en cada
corrida, historial del orquestador); data/raw/nvd_reconsulta/configs_vulnerable_20261003.csv.
Salidas (data/cleaned/bloque12b_latencia_deteccion/): resumen.csv, por_vulnerabilidad.csv
"""
import csv
import io
import statistics
import subprocess
from datetime import datetime
from inspect import currentframe
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
RAW = RAIZ / "data" / "raw"
SALIDA = RAIZ / "data" / "cleaned" / "bloque12b_latencia_deteccion"
CONTENEDOR = "postgres_db"
INICIO_CAMPANA = "2026-08-30 03:00"
SCRIPT = Path(__file__).name

RESUMEN = []


def reg(medida, unidad, valor):
    RESUMEN.append({"medida": medida, "unidad": unidad, "valor": valor,
                    "script": f"{SCRIPT}:{currentframe().f_back.f_lineno}"})


def consulta(sql):
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -c "COPY ({sql}) TO STDOUT WITH CSV HEADER"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return list(csv.DictReader(io.StringIO(texto)))


def fecha(texto):
    return datetime.fromisoformat(texto.replace(" ", "T")[:19])


def dias(desde, hasta):
    return (fecha(hasta) - fecha(desde)).total_seconds() / 86400


def tres(xs):
    return (round(min(xs), 1), round(statistics.median(xs), 1), round(max(xs), 1))


def main():
    pares = consulta("select cve_id, fuente_correlacion, fecha_publicacion_nvd, fecha_ingesta_pipeline "
                     f"from telemetria_vulnerabilidades where fecha_ingesta_pipeline >= '{INICIO_CAMPANA}'")
    corridas = sorted(r["timestamp"] for r in consulta(
        "select \\\"timestamp\\\" from auditoria_acciones where accion = 'INGESTA_DELTA'"))

    # Primera deteccion de cada vulnerabilidad por cada via.
    vias = {}
    for p in pares:
        v = vias.setdefault(p["cve_id"], {}).setdefault(p["fuente_correlacion"],
                                                       {"pub": p["fecha_publicacion_nvd"], "ing": p["fecha_ingesta_pipeline"]})
        v["ing"] = min(v["ing"], p["fecha_ingesta_pipeline"])

    vistas = {}
    with (RAW / "estado_al_ingerir.csv").open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["cve_id"] in vias:
                vistas.setdefault(r["cve_id"], []).append((r["ts_utc"], int(r["n_configs"])))
    with (RAW / "nvd_reconsulta" / "configs_vulnerable_20261003.csv").open(encoding="utf-8") as f:
        foto = {r["cve_id"]: r for r in csv.DictReader(f) if r["cve_id"] in vias}

    filas = []
    for cve in sorted(vias):
        vs = sorted(vistas[cve])
        pub = foto[cve]["published"]
        fila = {"cve_id": cve, "publicacion_utc": pub[:19], "corridas_que_la_vieron": len(vs),
                "dias_hasta_el_dato_min": "", "dias_hasta_el_dato_max": ""}
        if vs[0][1] > 0:
            fila["momento_del_dato"] = "primera_corrida"
        elif any(n > 0 for _, n in vs):
            fila["momento_del_dato"] = "dentro_de_la_ventana"
            d = dias(pub, next(t for t, n in vs if n > 0))
            fila["dias_hasta_el_dato_min"] = fila["dias_hasta_el_dato_max"] = round(d, 2)
        elif int(foto[cve]["n_configs"]) > 0:
            fila["momento_del_dato"] = "despues_de_la_ventana"
            fila["dias_hasta_el_dato_min"] = round(dias(pub, [t for t, n in vs if n == 0][-1]), 2)
            fila["dias_hasta_el_dato_max"] = round(dias(pub, foto[cve]["last_modified"]), 2)
        else:
            fila["momento_del_dato"] = "sin_dato_al_3_10"
            fila["dias_hasta_el_dato_min"] = round(dias(pub, "2026-10-03T00:00:00"), 2)
        for via, nombre in (("NVD", "formal"), ("HEURISTICA", "inferencia")):
            v = vias[cve].get(via)
            if v:
                previas = sum(v["pub"] < t < v["ing"] and dias(t, v["ing"]) * 1440 > 5 for t in corridas)
                fila[f"deteccion_{nombre}_horas"] = round(dias(v["pub"], v["ing"]) * 24, 1)
                fila[f"deteccion_{nombre}_corridas_previas"] = previas
        filas.append(fila)

    reg("vulnerabilidades correlacionadas en la campana", "vulnerabilidades", len(filas))
    for m in ("primera_corrida", "dentro_de_la_ventana", "despues_de_la_ventana", "sin_dato_al_3_10"):
        g = [f for f in filas if f["momento_del_dato"] == m]
        reg(f"dato de la NVD: {m}", "vulnerabilidades", len(g))
        reg(f"dato de la NVD: {m} (%)", "% de vulnerabilidades", round(100 * len(g) / len(filas), 1))
        if m == "dentro_de_la_ventana":
            reg("dentro de la ventana: dias de la publicacion a la primera corrida con dato (min, mediana, max)",
                "dias", tres([f["dias_hasta_el_dato_min"] for f in g]))
        if m == "despues_de_la_ventana":
            reg("despues de la ventana: cota inferior (ultima corrida sin dato) (min, mediana, max)",
                "dias", tres([f["dias_hasta_el_dato_min"] for f in g]))
            reg("despues de la ventana: cota superior (ultima modificacion al 3/10) (min, mediana, max)",
                "dias", tres([f["dias_hasta_el_dato_max"] for f in g]))
        if m == "sin_dato_al_3_10":
            reg("sin dato: dias desde la publicacion al 3/10 (min, mediana, max)", "dias",
                tres([f["dias_hasta_el_dato_min"] for f in g]))

    for nombre in ("inferencia", "formal"):
        g = [f for f in filas if f"deteccion_{nombre}_horas" in f]
        primera = [f for f in g if f[f"deteccion_{nombre}_corridas_previas"] == 0]
        reg(f"via {nombre}: vulnerabilidades detectadas", "vulnerabilidades", len(g))
        reg(f"via {nombre}: detectadas en la primera corrida posterior a la publicacion", "vulnerabilidades", len(primera))
        reg(f"via {nombre}: detectadas en una corrida posterior", "vulnerabilidades", len(g) - len(primera))
        reg(f"via {nombre}: horas de la publicacion a la deteccion (min, mediana, max)", "horas",
            tres([f[f"deteccion_{nombre}_horas"] for f in g]))
        tarde = [f[f"deteccion_{nombre}_horas"] for f in g if f[f"deteccion_{nombre}_corridas_previas"] > 0]
        if tarde:
            reg(f"via {nombre}: horas hasta la deteccion de las detectadas en una corrida posterior (min, mediana, max)",
                "horas", tres(tarde))

    # Procesamiento por corrida (posteriores al control de ritmo, seccion 3.8). El flujo consulta la
    # probabilidad de explotacion por cada par correlacionado en la corrida, nuevo o no, con 120 ms
    # entre peticiones, y recien despues verifica si el par existe: el tiempo depende de los pares
    # correlacionados (campo `pares` de la auditoria), no de los nuevos.
    tiempos = consulta("select (fecha_ingesta_pipeline - interval '3 hours')::date as dia, count(*) as nuevos, "
                       "percentile_cont(0.5) within group (order by extract(epoch from fecha_alerta_generada - "
                       "fecha_ingesta_pipeline)) as segundos from telemetria_vulnerabilidades "
                       "where fecha_ingesta_pipeline >= '2026-09-09 03:00' group by 1")
    auditoria = consulta("select (\\\"timestamp\\\" - interval '3 hours')::date as dia, metadata_json->>'pares' as pares "
                         "from auditoria_acciones where accion = 'INGESTA_DELTA' and \\\"timestamp\\\" >= '2026-09-09 03:00'")
    correlacionados = {a["dia"]: int(a["pares"]) for a in auditoria}
    proc = [{"dia_local": t["dia"], "pares_correlacionados": correlacionados[t["dia"]], "pares_nuevos": int(t["nuevos"]),
             "segundos_mediana": round(float(t["segundos"]), 1),
             "segundos_por_par_correlacionado": round(float(t["segundos"]) / correlacionados[t["dia"]], 2)}
            for t in sorted(tiempos, key=lambda t: t["dia"])]
    reg("procesamiento: corridas con pares nuevos (posteriores al control de ritmo)", "corridas", len(proc))
    reg("procesamiento: corridas posteriores al control de ritmo sin pares nuevos", "corridas",
        len(correlacionados) - len(proc))
    reg("procesamiento: segundos por par correlacionado, corridas de 100 pares o mas (min, mediana, max)", "segundos",
        tuple(round(f(x), 2) for f in (min, statistics.median, max)
              for x in [[p["segundos_por_par_correlacionado"] for p in proc if p["pares_correlacionados"] >= 100]]))

    # Tiempo entre corridas efectivas consecutivas (tabla del bloque 8), agrupado por tramo.
    with (RAIZ / "paper" / "tables" / "t5_intervalo_periodicidad.csv").open(encoding="utf-8") as f:
        brechas = [(r["desde_local"], float(r["horas"])) for r in csv.DictReader(f)]
    for nombre, cond in (("menos de 23 horas", lambda h: h < 23), ("entre 23 y 25 horas", lambda h: 23 <= h <= 25),
                         ("entre 25 y 26 horas", lambda h: 25 < h <= 26), ("mas de 26 horas", lambda h: h > 26)):
        g = [h for _, h in brechas if cond(h)]
        reg(f"brechas entre corridas: {nombre}", "brechas", len(g))
        if g:
            reg(f"brechas entre corridas: {nombre} (min, max)", "horas", (min(g), max(g)))
    desde_13 = [h for d, h in brechas if d >= "2026-09-13"]
    reg("brechas desde la corrida del 13/09 (cantidad, min, max)", "horas", (len(desde_13), min(desde_13), max(desde_13)))

    SALIDA.mkdir(parents=True, exist_ok=True)
    with (SALIDA / "procesamiento_por_corrida.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(proc[0]))
        w.writeheader()
        w.writerows(proc)
    campos = list(dict.fromkeys(k for f in filas for k in f))
    with (SALIDA / "por_vulnerabilidad.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=campos, restval="")
        w.writeheader()
        w.writerows(filas)
    with (SALIDA / "resumen.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["medida", "unidad", "valor", "script"])
        w.writeheader()
        w.writerows(RESUMEN)
    for r in RESUMEN:
        print(f"{r['medida']}: {r['valor']}")


if __name__ == "__main__":
    main()
