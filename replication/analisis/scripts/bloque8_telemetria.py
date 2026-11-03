"""Bloque 8 -- Extraccion de telemetria para el Capitulo 5: tablas y figuras.

Lee la base de investigacion (solo lectura, contenedor `postgres_db`) y la foto de la NVD del
3 de octubre (bloque 4B). No escribe en la base ni toca el artefacto. Cada cifra que el
capitulo reporta sale de este script y queda registrada en `paper/tables/cifras_capitulo5.csv`
con su unidad de computo, la tabla de la base de la que sale y la linea de este archivo que la
produce.

Unidades de computo (seccion 3.3):  cobertura -> vulnerabilidades distintas (y pares donde se
dice);  volumen de hallazgos y notificaciones -> pares;  rendimiento -> corridas efectivas.

Universos (Anexo D): CAMPANA = pares con ingesta desde el 30/08 00:00 locales (3.848);
TOTAL = toda la tabla (3.883, incluye 35 del periodo de estabilizacion). El contraste entre el
indice de la deteccion y el del cierre usa TOTAL (seccion 3.3); todo lo demas, CAMPANA.

Salidas: paper/tables/*.csv (sin titulos ni notas; los pone el documento) y
paper/figures/*.png (sin titulos dentro de la figura; el titulo va en el epigrafe).
"""
import csv
import io
import json
import statistics
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from inspect import currentframe
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
matplotlib.rcParams["font.family"] = "serif"
import matplotlib.pyplot as plt  # noqa: E402

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bloque1_cobertura_cierre import claves_cpe, leer_csv  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
RAW = RAIZ / "data" / "raw"
TABLAS = RAIZ / "paper" / "tables"
FIGURAS = RAIZ / "paper" / "figures"
CONTENEDOR = "postgres_db"
SCRIPT = Path(__file__).name

# Frontera de la campana: 30/08 00:00 locales = 03:00 UTC (las marcas de la base estan en UTC).
INICIO_CAMPANA = "2026-08-30 03:00"
HUSO_LOCAL = timedelta(hours=-3)
# Pesos y umbrales del indice, seccion 3.6 (congelados antes de abrir la recoleccion).
PESOS = {"cvss": 0.15, "epss": 0.25, "kev": 0.30, "crit": 0.20, "exp": 0.10}
UMBRAL_CRITICA, UMBRAL_ALTA = 0.70, 0.40
# Dia local desde el que corre el control de ritmo entre peticiones (seccion 3.8).
DIA_CONTROL_RITMO = "2026-09-09"
DIA_REPARADO_A_MANO = "2026-09-03"

CIFRAS = []


def cifra(nombre, valor, unidad, universo, fuente, linea):
    """Registra una cifra del capitulo con la linea de este script que la produce."""
    CIFRAS.append({"cifra": nombre, "valor": valor, "unidad_de_computo": unidad,
                   "universo": universo, "fuente": fuente, "script": f"{SCRIPT}:{linea}"})


def linea():
    return currentframe().f_back.f_lineno


def consulta(sql):
    """Ejecuta una consulta de solo lectura y devuelve las filas como diccionarios."""
    cmd = ["docker", "exec", "-i", CONTENEDOR, "sh", "-c",
           'psql -U "$POSTGRES_USER" -d secops_research_db --csv']
    r = subprocess.run(cmd, input=sql, capture_output=True, text=True, encoding="utf-8", check=True)
    return list(csv.DictReader(io.StringIO(r.stdout)))


def escribir(nombre, filas):
    TABLAS.mkdir(parents=True, exist_ok=True)
    campos = list(dict.fromkeys(k for f in filas for k in f))
    with (TABLAS / nombre).open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=campos, restval="")
        w.writeheader()
        w.writerows(filas)


def guardar_figura(fig, nombre):
    FIGURAS.mkdir(parents=True, exist_ok=True)
    fig.savefig(FIGURAS / nombre, dpi=200, bbox_inches="tight")
    plt.close(fig)


def rotulo(ax, texto):
    """Rotulo de panel, fuera del area de dibujo para no tapar datos."""
    ax.text(0, 1.03, texto, transform=ax.transAxes, va="bottom", fontsize=9, fontweight="bold")


def pct(n, d):
    return round(100 * n / d, 1) if d else None


def cuantiles(xs):
    """Minimo, cuartiles, p90 y maximo (metodo inclusivo)."""
    q = statistics.quantiles(xs, n=100, method="inclusive")
    return {"min": min(xs), "p25": q[24], "mediana": q[49], "p75": q[74], "p90": q[89], "max": max(xs)}


def f4(x):
    return round(x, 4)


def clasificar(irc):
    return "CRITICA" if irc >= UMBRAL_CRITICA else "ALTA" if irc >= UMBRAL_ALTA else "INFORMATIVA"


# ---------------------------------------------------------------------------------------------
# Carga
# ---------------------------------------------------------------------------------------------

# Todas las filas de telemetria con el insumo del indice. `crit` es el peso ya normalizado de
# la tabla de referencia (columna generada); `local_ingesta` es la marca de ingesta en hora local.
SQL_PARES = f"""
SELECT t.id, t.cve_id, t.activo_id, a.hostname, a.criticidad_id, a.exposicion_internet::int AS exp,
       c.peso_normalizacion AS crit,
       t.cvss_score, t.epss_score, t.kev_status::int AS kev, t.irc_score, t.prioridad, t.estado,
       t.cvss_score_final, t.epss_score_final, t.kev_status_final::int AS kev_final, t.irc_score_final,
       t.fuente_correlacion, t.nivel_confianza, COALESCE(t.fuente_correlacion_final, '') AS fuente_final,
       t.fecha_publicacion_nvd, t.fecha_ingesta_pipeline, t.fecha_alerta_generada,
       t.fecha_enriquecimiento_nvd, t.fecha_promocion_detectada,
       (t.fecha_ingesta_pipeline >= '{INICIO_CAMPANA}')::int AS campana
FROM telemetria_vulnerabilidades t
JOIN activos a ON a.id = t.activo_id
JOIN criticidad_niveles c ON c.id = a.criticidad_id
ORDER BY t.id;
"""

# Las 28 filas de auditoria de la recoleccion. La lista `ids` es lo que la corrida correlaciono.
SQL_AUDITORIA = f"""
SELECT id, "timestamp" AS ts_utc,
       (metadata_json->>'cve_ingeridos')::int AS ingeridos,
       (metadata_json->>'correlacionados')::int AS correlacionados,
       (metadata_json->>'n1')::int AS n1_formal, (metadata_json->>'n2')::int AS n2,
       (metadata_json->>'n3')::int AS n3, (metadata_json->>'n4')::int AS n4_inferencia,
       (metadata_json->>'pares')::int AS pares_auditoria,
       metadata_json->'ids' AS ids
FROM auditoria_acciones
WHERE accion = 'INGESTA_DELTA' AND "timestamp" >= '{INICIO_CAMPANA}'
ORDER BY id;
"""

SQL_ACTIVOS = "SELECT id, hostname, criticidad_id, exposicion_internet::int AS exp FROM activos ORDER BY id;"


def a_dt(texto):
    return datetime.fromisoformat(texto) if texto else None


def cargar():
    pares = consulta(SQL_PARES)
    for p in pares:
        for k in ("id", "activo_id", "criticidad_id", "exp", "campana"):
            p[k] = int(p[k])
        for k in ("crit", "cvss_score", "epss_score", "irc_score", "cvss_score_final",
                  "epss_score_final", "irc_score_final"):
            p[k] = float(p[k])
        p["kev"] = int(p["kev"])
        p["kev_final"] = int(p["kev_final"])
        for k in ("fecha_publicacion_nvd", "fecha_ingesta_pipeline", "fecha_alerta_generada",
                  "fecha_enriquecimiento_nvd", "fecha_promocion_detectada"):
            p[k] = a_dt(p[k])
        p["dia_local"] = (p["fecha_ingesta_pipeline"] + HUSO_LOCAL).date().isoformat()
    audit = consulta(SQL_AUDITORIA)
    for r in audit:
        r["id"] = int(r["id"])
        r["ts"] = a_dt(r["ts_utc"])
        for k in ("ingeridos", "correlacionados", "n1_formal", "n2", "n3", "n4_inferencia", "pares_auditoria"):
            r[k] = int(r[k])
        r["ids"] = json.loads(r["ids"])
        r["dia_local"] = (r["ts"] + HUSO_LOCAL).date().isoformat()
    activos = {int(a["id"]): a for a in consulta(SQL_ACTIVOS)}
    return pares, audit, activos


def foto_nvd(activos_cpe):
    """Estado de cada vulnerabilidad en la foto del 3/10: activos que coinciden segun las dos reglas."""
    ruta = sorted((RAW / "nvd_reconsulta").glob("configs_vulnerable_*.csv"))[-1]
    meta = json.loads(sorted((RAW / "nvd_reconsulta").glob("meta_configs_vulnerable_*.json"))[-1]
                      .read_text(encoding="utf-8"))

    def coinciden(cpes):
        claves = {k for c in cpes.split() for k in claves_cpe(c)}
        return {aid for aid, ks in activos_cpe.items() if any(k in claves for k in ks)}

    estado = {}
    for c in leer_csv(ruta):
        vuln, plat = coinciden(c["cpes_vulnerables"]), coinciden(c["cpes_plataforma"])
        estado[c["cve_id"]] = {"pub": c["published"], "artefacto": vuln | plat, "vulnerable": vuln}
    return estado, meta


# ---------------------------------------------------------------------------------------------
# 1. Cobertura por via, al detectar y al cierre, y por activo
# ---------------------------------------------------------------------------------------------

def seccion_cobertura(pares, audit, activos, estado, nombre_activo):
    camp = [p for p in pares if p["campana"]]
    ultima = max(r["ts_utc"] for r in audit).replace(" ", "T")
    visibles = {k for k, v in estado.items() if v["pub"] <= ultima}

    # 1a. Al detectar, por corrida: lo que la fila de auditoria registra (unidad: vulnerabilidades
    # distintas por corrida; las ventanas se superponen, de modo que no se suman entre corridas).
    previo, filas = None, []
    for r in audit:
        efectiva = previo is None or r["dia_local"] != previo
        previo = r["dia_local"]
        filas.append({"fila_auditoria": r["id"], "dia_local": r["dia_local"], "corrida_efectiva": int(efectiva),
                      "ingeridos": r["ingeridos"], "correlacionados": r["correlacionados"],
                      "formal_nvd": r["n1_formal"], "inferencia": r["n4_inferencia"],
                      "cobertura_pct": pct(r["correlacionados"], r["ingeridos"])})
    escribir("t5_cobertura_deteccion_por_corrida.csv", filas)
    efectivas = [f for f in filas if f["corrida_efectiva"]]
    cifra("corridas de auditoria de la recoleccion", len(filas), "filas de auditoria", "campana",
          "auditoria_acciones", linea())
    cifra("corridas efectivas", len(efectivas), "corridas efectivas", "campana", "auditoria_acciones", linea())
    cifra("cobertura de deteccion por corrida: mediana", round(statistics.median(f["cobertura_pct"] for f in efectivas), 2),
          "% de vulnerabilidades ingeridas, por corrida", "corridas efectivas", "auditoria_acciones", linea())

    # 1b. Por via, vulnerabilidades distintas en toda la campana, al detectar y al cierre.
    detectadas = {i for r in audit for i in r["ids"]}
    detectadas_formal = {p["cve_id"] for p in camp if p["fuente_correlacion"] == "NVD"}
    detectadas_inf = {p["cve_id"] for p in camp if p["fuente_correlacion"] == "HEURISTICA"}
    promovidas = {p["cve_id"] for p in camp if p["fuente_final"] == "NVD"}
    por_via = [
        {"momento": "deteccion", "via": "formal (NVD)", "vulnerabilidades": len(detectadas_formal), "pares": sum(p["fuente_correlacion"] == "NVD" for p in camp)},
        {"momento": "deteccion", "via": "inferencia", "vulnerabilidades": len(detectadas_inf), "pares": sum(p["fuente_correlacion"] == "HEURISTICA" for p in camp)},
        {"momento": "deteccion", "via": "cualquiera (union)", "vulnerabilidades": len(detectadas_formal | detectadas_inf), "pares": len(camp)},
        {"momento": "cierre", "via": "inferencia con confirmacion formal posterior", "vulnerabilidades": len(promovidas), "pares": sum(p["fuente_final"] == "NVD" for p in camp)},
    ]
    escribir("t5_cobertura_por_via.csv", por_via)
    cifra("vulnerabilidades detectadas por la via formal", len(detectadas_formal), "vulnerabilidades distintas", "campana", "telemetria_vulnerabilidades.fuente_correlacion", linea())
    cifra("vulnerabilidades detectadas por la via de inferencia", len(detectadas_inf), "vulnerabilidades distintas", "campana", "telemetria_vulnerabilidades.fuente_correlacion", linea())
    cifra("vulnerabilidades detectadas por alguna via (telemetria)", len(detectadas_formal | detectadas_inf), "vulnerabilidades distintas", "campana", "telemetria_vulnerabilidades", linea())
    cifra("vulnerabilidades detectadas (lista `ids` de la auditoria)", len(detectadas), "vulnerabilidades distintas", "campana", "auditoria_acciones.metadata_json.ids", linea())
    cifra("pares inferidos promovidos a formal despues", sum(p["fuente_final"] == "NVD" for p in camp), "pares", "campana", "telemetria_vulnerabilidades.fuente_correlacion_final", linea())

    # 1c. Al cierre: contra lo que la NVD termino vinculando (foto del 3/10), con las dos reglas.
    persistidos = {(p["cve_id"], p["activo_id"]): p for p in camp}
    cierre = []
    for regla in ("artefacto", "vulnerable"):
        formal = {k for k in visibles if estado[k][regla]}
        pares_formales = [(k, a) for k in formal for a in estado[k][regla]]
        pares_det = [x for x in pares_formales if x in persistidos]
        cierre.append({"regla": regla, "vulnerabilidades_formales_hoy": len(formal),
                       "detectadas": len(formal & detectadas), "cobertura_vuln_pct": pct(len(formal & detectadas), len(formal)),
                       "pares_formales_hoy": len(pares_formales), "pares_persistidos": len(pares_det),
                       "cobertura_pares_pct": pct(len(pares_det), len(pares_formales))})
        cifra(f"cierre ({regla}): vulnerabilidades con coincidencia formal", len(formal), "vulnerabilidades distintas", "foto NVD 03/10 visibles", "configs_vulnerable_*.csv", linea())
        cifra(f"cierre ({regla}): cobertura por vulnerabilidad", pct(len(formal & detectadas), len(formal)), "% de vulnerabilidades distintas", "foto NVD 03/10 visibles", "auditoria ids / configs_vulnerable", linea())
        cifra(f"cierre ({regla}): cobertura por par", pct(len(pares_det), len(pares_formales)), "% de pares", "foto NVD 03/10 visibles", "telemetria / configs_vulnerable", linea())
    escribir("t5_cobertura_cierre.csv", cierre)

    # 1d. Por activo (regla del artefacto): categoria de cada par formal de hoy segun como lo trato el flujo.
    cat = defaultdict(Counter)
    for k in visibles:
        for a in estado[k]["artefacto"]:
            p = persistidos.get((k, a))
            if p is None:
                c = "no_persistido"
            elif p["fuente_correlacion"] == "NVD":
                c = "formal_al_detectar"
            elif p["fuente_final"] == "NVD":
                c = "inferido_y_promovido"
            else:
                c = "inferido_sin_promocion"
            cat[a][c] += 1
    por_activo = []
    for aid, a in activos.items():
        propios = [p for p in camp if p["activo_id"] == aid]
        c = cat[aid]
        formales = sum(c.values())
        por_activo.append({
            "activo_id": aid, "hostname": a["hostname"], "criticidad": int(a["criticidad_id"]), "expuesto": int(a["exp"]),
            "pares_persistidos": len(propios),
            "persistidos_formal": sum(p["fuente_correlacion"] == "NVD" for p in propios),
            "persistidos_inferencia": sum(p["fuente_correlacion"] == "HEURISTICA" for p in propios),
            "pares_formales_hoy": formales,
            "formal_al_detectar": c["formal_al_detectar"], "inferido_y_promovido": c["inferido_y_promovido"],
            "inferido_sin_promocion": c["inferido_sin_promocion"], "no_persistido": c["no_persistido"],
            "cobertura_cierre_pct": pct(formales - c["no_persistido"], formales)})
    escribir("t5_cobertura_por_activo.csv", por_activo)
    con = [a for a in por_activo if a["pares_formales_hoy"]]
    cifra("activos con al menos un par formal de hoy", len(con), "activos", "foto NVD 03/10", "configs_vulnerable_*.csv", linea())
    cifra("activos sin ningun par persistido en la campana", sum(a["pares_persistidos"] == 0 for a in por_activo), "activos", "campana", "telemetria_vulnerabilidades", linea())
    for a in por_activo:
        if a["pares_formales_hoy"] and a["no_persistido"]:
            cifra(f"{a['hostname']}: pares formales de hoy no persistidos", a["no_persistido"], "pares", "foto NVD 03/10 visibles", "telemetria / configs_vulnerable", linea())

    # Figura: cobertura al cierre por activo, por via (activos con pares formales hoy).
    con = sorted(con, key=lambda a: -a["pares_formales_hoy"])
    fig, ax = plt.subplots(figsize=(8, 0.34 * len(con) + 1.2))
    izq = [0] * len(con)
    for clave, rotulo, color in (("formal_al_detectar", "Formal al detectar", "#2b6c8f"),
                                 ("inferido_y_promovido", "Inferido, luego confirmado", "#7fb3d5"),
                                 ("inferido_sin_promocion", "Inferido, sin confirmación", "#e0a458"),
                                 ("no_persistido", "No detectado", "#b0443c")):
        vals = [a[clave] for a in con]
        ax.barh([a["hostname"] for a in con], vals, left=izq, label=rotulo, color=color)
        izq = [i + v for i, v in zip(izq, vals)]
    ax.invert_yaxis()
    ax.set_xlabel("Pares vulnerabilidad-activo con coincidencia formal al 3/10")
    ax.legend(frameon=False, loc="lower right")
    guardar_figura(fig, "fig5_cobertura_por_activo.png")
    return por_activo


# ---------------------------------------------------------------------------------------------
# 2. Distribucion del indice y de sus cinco componentes (campana)
# ---------------------------------------------------------------------------------------------

def seccion_indice(pares):
    camp = [p for p in pares if p["campana"]]
    comp = {"cvss": [p["cvss_score"] / 10 for p in camp], "epss": [p["epss_score"] for p in camp],
            "kev": [float(p["kev"]) for p in camp], "crit": [p["crit"] for p in camp],
            "exp": [float(p["exp"]) for p in camp]}
    irc = [p["irc_score"] for p in camp]
    # Control: el indice recalculado desde sus componentes coincide con el persistido.
    dif = max(abs(sum(PESOS[k] * comp[k][i] for k in PESOS) - irc[i]) for i in range(len(camp)))
    cifra("diferencia maxima entre el indice persistido y el recalculado desde sus componentes", f4(dif), "unidades de indice", "campana", "telemetria_vulnerabilidades", linea())
    cifra("filas cuya prioridad no corresponde a su indice", sum(clasificar(p["irc_score"]) != p["prioridad"] for p in camp), "pares", "campana", "telemetria_vulnerabilidades", linea())

    filas = []
    n = len(camp)
    for k in PESOS:
        xs = comp[k]
        q = cuantiles(xs)
        aporte = [PESOS[k] * x for x in xs]
        filas.append({"componente": k, "peso": PESOS[k], "media": f4(statistics.mean(xs)), **{a: f4(b) for a, b in q.items()},
                      "pares_con_valor_distinto_de_cero": sum(x > 0 for x in xs),
                      "aporte_medio_al_indice": f4(statistics.mean(aporte)),
                      "aporte_pct_del_indice_medio": pct(statistics.mean(aporte), statistics.mean(irc))})
    q = cuantiles(irc)
    filas.append({"componente": "indice", "peso": 1.0, "media": f4(statistics.mean(irc)), **{a: f4(b) for a, b in q.items()},
                  "pares_con_valor_distinto_de_cero": sum(x > 0 for x in irc), "aporte_medio_al_indice": f4(statistics.mean(irc)),
                  "aporte_pct_del_indice_medio": 100.0})
    escribir("t5_indice_componentes.csv", filas)
    cifra("pares de la campana", n, "pares", "campana", "telemetria_vulnerabilidades", linea())
    cifra("indice al detectar: mediana", f4(q["mediana"]), "indice [0,1]", "campana", "telemetria_vulnerabilidades.irc_score", linea())
    cifra("indice al detectar: maximo", f4(q["max"]), "indice [0,1]", "campana", "telemetria_vulnerabilidades.irc_score", linea())
    cifra("indice al detectar: p90", f4(q["p90"]), "indice [0,1]", "campana", "telemetria_vulnerabilidades.irc_score", linea())

    # Distribucion por prioridad, y concentracion del indice en los dos componentes que lo mueven.
    prio = Counter(p["prioridad"] for p in camp)
    escribir("t5_prioridad.csv", [{"prioridad": k, "pares": prio.get(k, 0), "pct": pct(prio.get(k, 0), n)}
                                  for k in ("CRITICA", "ALTA", "INFORMATIVA")])
    for k in ("CRITICA", "ALTA", "INFORMATIVA"):
        cifra(f"pares de prioridad {k.lower()} al detectar", prio.get(k, 0), "pares", "campana", "telemetria_vulnerabilidades.prioridad", linea())
    cifra("pares con KEV = 1 al detectar", sum(p["kev"] for p in camp), "pares", "campana", "telemetria_vulnerabilidades.kev_status", linea())
    cifra("pares con EPSS = 0 al detectar", sum(p["epss_score"] == 0 for p in camp), "pares", "campana", "telemetria_vulnerabilidades.epss_score", linea())

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 3.8), gridspec_kw={"width_ratios": [3, 2], "wspace": 0.75})
    ax1.hist(irc, bins=40, color="#2b6c8f")
    ax1.set_yscale("log")
    for u, r in ((UMBRAL_ALTA, "0,40"), (UMBRAL_CRITICA, "0,70")):
        ax1.axvline(u, color="#b0443c", linestyle="--", linewidth=1)
        ax1.text(u, ax1.get_ylim()[1], f" {r}", color="#b0443c", va="top", fontsize=8)
    ax1.set_xlabel("Índice de Riesgo Compuesto al detectar")
    ax1.set_ylabel("Pares (escala logarítmica)")
    rotulo(ax1, "Panel A")
    nombres = {"cvss": "Severidad", "epss": "Prob. explotación", "kev": "Explotación confirmada", "crit": "Criticidad", "exp": "Exposición"}
    medias = [f["aporte_medio_al_indice"] for f in filas[:5]]
    ax2.barh([nombres[k] for k in PESOS], medias, color="#7fb3d5")
    ax2.invert_yaxis()
    ax2.set_xlabel("Aporte medio al índice (peso × valor)")
    rotulo(ax2, "Panel B")
    guardar_figura(fig, "fig5_indice_distribucion.png")


# ---------------------------------------------------------------------------------------------
# 3. Contraste: indice al detectar contra el recalculado con informacion madura (universo TOTAL)
# ---------------------------------------------------------------------------------------------

def seccion_contraste(pares):
    n = len(pares)
    delta = [p["irc_score_final"] - p["irc_score"] for p in pares]
    dif = max(abs(sum(w * v for w, v in zip(PESOS.values(),
              (p["cvss_score_final"] / 10, p["epss_score_final"], p["kev_final"], p["crit"], p["exp"]))) - p["irc_score_final"])
              for p in pares)
    cifra("diferencia maxima entre el indice de cierre persistido y el recalculado", f4(dif), "unidades de indice", "total", "telemetria_vulnerabilidades.irc_score_final", linea())
    cifra("pares del contraste", n, "pares", "total", "telemetria_vulnerabilidades", linea())
    q = cuantiles(delta)
    cifra("diferencia de indice (cierre - deteccion): mediana", f4(q["mediana"]), "unidades de indice", "total", "irc_score_final - irc_score", linea())
    cifra("diferencia de indice: maxima", f4(q["max"]), "unidades de indice", "total", "irc_score_final - irc_score", linea())
    cifra("diferencia de indice: minima", f4(q["min"]), "unidades de indice", "total", "irc_score_final - irc_score", linea())
    cifra("pares cuyo indice sube", sum(d > 0 for d in delta), "pares", "total", "irc_score_final - irc_score", linea())
    cifra("pares cuyo indice baja", sum(d < 0 for d in delta), "pares", "total", "irc_score_final - irc_score", linea())
    cifra("pares cuyo indice no cambia", sum(d == 0 for d in delta), "pares", "total", "irc_score_final - irc_score", linea())

    # Aporte de cada componente al desplazamiento (peso x cambio del componente).
    cambios = {"cvss": [(p["cvss_score_final"] - p["cvss_score"]) / 10 for p in pares],
               "epss": [p["epss_score_final"] - p["epss_score"] for p in pares],
               "kev": [float(p["kev_final"] - p["kev"]) for p in pares]}
    filas = [{"componente": k, "peso": PESOS[k], "pares_que_cambian": sum(x != 0 for x in v),
              "cambio_medio_del_componente": f4(statistics.mean(v)),
              "aporte_medio_al_desplazamiento": f4(PESOS[k] * statistics.mean(v))} for k, v in cambios.items()]
    escribir("t5_contraste_componentes.csv", filas)
    for f in filas:
        cifra(f"{f['componente']}: pares cuyo valor cambia entre deteccion y cierre", f["pares_que_cambian"], "pares", "total", "campos *_final", linea())

    # Cambio de prioridad.
    trans = Counter((p["prioridad"], clasificar(p["irc_score_final"])) for p in pares)
    escribir("t5_contraste_prioridad.csv", [{"prioridad_deteccion": a, "prioridad_cierre": b, "pares": c}
                                            for (a, b), c in sorted(trans.items())])
    cifra("pares que cambian de prioridad", sum(c for (a, b), c in trans.items() if a != b), "pares", "total", "prioridad vs irc_score_final", linea())
    cifra("pares notificables (prioridad no informativa) al detectar", sum(p["prioridad"] != "INFORMATIVA" for p in pares), "pares", "total", "telemetria_vulnerabilidades.prioridad", linea())
    cifra("pares notificables al cierre", sum(clasificar(p["irc_score_final"]) != "INFORMATIVA" for p in pares), "pares", "total", "irc_score_final", linea())

    fig, ax = plt.subplots(figsize=(5.2, 4.6))
    ax.scatter([p["irc_score"] for p in pares], [p["irc_score_final"] for p in pares], s=6, alpha=0.35, color="#2b6c8f", linewidths=0)
    ax.plot([0, 1], [0, 1], color="grey", linewidth=0.8)
    for u in (UMBRAL_ALTA, UMBRAL_CRITICA):
        ax.axvline(u, color="#b0443c", linestyle="--", linewidth=0.8)
        ax.axhline(u, color="#b0443c", linestyle="--", linewidth=0.8)
    ax.set_xlabel("Índice al detectar")
    ax.set_ylabel("Índice recalculado al cierre")
    ax.set_xlim(0, 0.85)
    ax.set_ylim(0, 0.85)
    guardar_figura(fig, "fig5_contraste_indice.png")


# ---------------------------------------------------------------------------------------------
# 4 y 7. Los tres intervalos de tiempo y las filas excluidas del de procesamiento
# ---------------------------------------------------------------------------------------------

def grupo_intervalo(dia_local):
    if dia_local == DIA_REPARADO_A_MANO:
        return "excluida_reparada_a_mano"
    if dia_local < DIA_CONTROL_RITMO:
        return "previa_al_control_de_ritmo"
    return "posterior_al_control_de_ritmo"


def seccion_intervalos(pares, audit):
    camp = [p for p in pares if p["campana"]]

    # 4a. Procesamiento: de la marca de ingesta (una por corrida) al cierre del procesamiento de la fila.
    for p in camp:
        p["seg"] = (p["fecha_alerta_generada"] - p["fecha_ingesta_pipeline"]).total_seconds()
        p["grupo_intervalo"] = grupo_intervalo(p["dia_local"])
    por_corrida = defaultdict(list)
    for p in camp:
        por_corrida[p["fecha_ingesta_pipeline"]].append(p)
    filas = []
    for ing, g in sorted(por_corrida.items()):
        s = [p["seg"] for p in g]
        filas.append({"ingesta_utc": ing.isoformat(sep=" ", timespec="seconds"), "dia_local": g[0]["dia_local"], "pares": len(g),
                      "segundos_min": round(min(s), 1), "segundos_mediana": round(statistics.median(s), 1),
                      "segundos_max": round(max(s), 1), "grupo": g[0]["grupo_intervalo"]})
    escribir("t5_intervalo_procesamiento_por_corrida.csv", filas)

    resumen = []
    for grupo in ("posterior_al_control_de_ritmo", "previa_al_control_de_ritmo", "excluida_reparada_a_mano"):
        g = [p for p in camp if p["grupo_intervalo"] == grupo]
        corridas = [f for f in filas if f["grupo"] == grupo]
        q = cuantiles([p["seg"] for p in g])
        resumen.append({"grupo": grupo, "corridas": len(corridas), "pares": len(g),
                        "segundos_min": round(q["min"], 1), "segundos_mediana": round(q["mediana"], 1),
                        "segundos_p90": round(q["p90"], 1), "segundos_max": round(q["max"], 1),
                        "mediana_de_medianas_por_corrida": round(statistics.median(f["segundos_mediana"] for f in corridas), 1),
                        "se_reporta": "no" if grupo == "excluida_reparada_a_mano" else ("no (no comparable)" if grupo.startswith("previa") else "si")})
        cifra(f"intervalo de procesamiento, {grupo}: pares", len(g), "pares", "campana", "fecha_alerta_generada - fecha_ingesta_pipeline", linea())
    escribir("t5_intervalo_procesamiento_resumen.csv", resumen)
    post = [p["seg"] for p in camp if p["grupo_intervalo"] == "posterior_al_control_de_ritmo"]
    qp = cuantiles(post)
    cifra("intervalo de procesamiento (posterior al control de ritmo): mediana", round(qp["mediana"], 1), "segundos por par", "pares posteriores", "fecha_alerta_generada - fecha_ingesta_pipeline", linea())
    cifra("intervalo de procesamiento (posterior): p90", round(qp["p90"], 1), "segundos por par", "pares posteriores", "fecha_alerta_generada - fecha_ingesta_pipeline", linea())
    cifra("intervalo de procesamiento (posterior): maximo", round(qp["max"], 1), "segundos por par", "pares posteriores", "fecha_alerta_generada - fecha_ingesta_pipeline", linea())
    rep = [p["seg"] for p in camp if p["grupo_intervalo"] == "excluida_reparada_a_mano"]
    cifra("filas de la corrida del 3/09 excluidas del intervalo", len(rep), "pares", "campana", "fecha_alerta_generada - fecha_ingesta_pipeline", linea())
    cifra("filas de la corrida del 3/09: intervalo observado", round(statistics.median(rep) / 60, 1), "minutos", "campana", "fecha_alerta_generada - fecha_ingesta_pipeline", linea())
    cifra("filas anteriores al control de ritmo (sin la del 3/09)", sum(p["grupo_intervalo"] == "previa_al_control_de_ritmo" for p in camp), "pares", "campana", "dia local de la ingesta", linea())

    # 4b. Publicacion del dato formal: de la publicacion de la vulnerabilidad al lastModified con que el
    # NIST la enriquecio (aproximacion declarada en el Anexo C: el NIST estampa el campo por lotes).
    prom = [p for p in pares if p["fecha_enriquecimiento_nvd"] and p["fecha_publicacion_nvd"]]
    dias = [(p["fecha_enriquecimiento_nvd"] - p["fecha_publicacion_nvd"]).total_seconds() / 86400 for p in prom]
    escribir("t5_intervalo_publicacion_formal.csv",
             [{"cve_id": p["cve_id"], "activo_id": p["activo_id"], "campana": p["campana"],
               "dias_publicacion_a_enriquecimiento": round(d, 2)} for p, d in zip(prom, dias)])
    qd = cuantiles(dias)
    cifra("pares promovidos a vulnerabilidad formal", len(prom), "pares", "total", "fecha_enriquecimiento_nvd no nula", linea())
    cifra("vulnerabilidades distintas promovidas", len({p["cve_id"] for p in prom}), "vulnerabilidades distintas", "total", "fecha_enriquecimiento_nvd no nula", linea())
    cifra("latencia de enriquecimiento de la fuente: mediana", round(qd["mediana"], 1), "dias", "pares promovidos", "fecha_enriquecimiento_nvd - fecha_publicacion_nvd", linea())
    cifra("latencia de enriquecimiento: p25", round(qd["p25"], 1), "dias", "pares promovidos", "fecha_enriquecimiento_nvd - fecha_publicacion_nvd", linea())
    cifra("latencia de enriquecimiento: p75", round(qd["p75"], 1), "dias", "pares promovidos", "fecha_enriquecimiento_nvd - fecha_publicacion_nvd", linea())
    cifra("latencia de enriquecimiento: minima", round(qd["min"], 1), "dias", "pares promovidos", "fecha_enriquecimiento_nvd - fecha_publicacion_nvd", linea())
    cifra("latencia de enriquecimiento: maxima", round(qd["max"], 1), "dias", "pares promovidos", "fecha_enriquecimiento_nvd - fecha_publicacion_nvd", linea())

    # 4c. Periodicidad del disparador: horas entre corridas efectivas consecutivas.
    efectivas, previo = [], None
    for r in audit:
        if r["dia_local"] != previo:
            efectivas.append(r)
        previo = r["dia_local"]
    brechas = [(b["ts"] - a["ts"]).total_seconds() / 3600 for a, b in zip(efectivas, efectivas[1:])]
    escribir("t5_intervalo_periodicidad.csv",
             [{"desde_fila": a["id"], "hasta_fila": b["id"], "desde_local": (a["ts"] + HUSO_LOCAL).isoformat(sep=" ", timespec="minutes"),
               "hasta_local": (b["ts"] + HUSO_LOCAL).isoformat(sep=" ", timespec="minutes"), "horas": round(h, 2)}
              for a, b, h in zip(efectivas, efectivas[1:], brechas)])
    qh = cuantiles(brechas)
    cifra("brechas entre corridas efectivas consecutivas", len(brechas), "brechas", "corridas efectivas", "auditoria_acciones.timestamp", linea())
    cifra("periodicidad: mediana", round(qh["mediana"], 1), "horas", "corridas efectivas", "auditoria_acciones.timestamp", linea())
    cifra("periodicidad: maxima", round(qh["max"], 1), "horas", "corridas efectivas", "auditoria_acciones.timestamp", linea())
    cifra("periodicidad: minima", round(qh["min"], 1), "horas", "corridas efectivas", "auditoria_acciones.timestamp", linea())
    cifra("brechas de mas de 26 horas", sum(h > 26 for h in brechas), "brechas", "corridas efectivas", "auditoria_acciones.timestamp", linea())

    fig, (a1, a2, a3) = plt.subplots(1, 3, figsize=(13, 3.8), gridspec_kw={"wspace": 0.3})
    posteriores = [f for f in filas if f["grupo"] == "posterior_al_control_de_ritmo"]
    a1.bar(range(len(posteriores)), [f["segundos_mediana"] for f in posteriores], color="#2b6c8f")
    a1.set_xticks(range(len(posteriores)))
    a1.set_xticklabels([f["dia_local"][5:] for f in posteriores], rotation=60, fontsize=7)
    a1.set_ylabel("Segundos de ingesta a cierre\n(mediana de la corrida)")
    a1.set_xlabel("Corrida (fecha local)")
    rotulo(a1, "Panel A")
    a2.hist(dias, bins=15, color="#7fb3d5")
    a2.set_xlabel("Días de la publicación al enriquecimiento")
    a2.set_ylabel("Pares promovidos")
    rotulo(a2, "Panel B")
    a3.bar(range(len(brechas)), brechas, color="#e0a458")
    a3.axhline(24, color="grey", linewidth=0.8, linestyle="--")
    a3.set_xlabel("Brecha entre corridas efectivas consecutivas")
    a3.set_ylabel("Horas")
    rotulo(a3, "Panel C")
    guardar_figura(fig, "fig5_intervalos.png")

    # 7. Filas excluidas del intervalo de procesamiento, una por una.
    escribir("t5_filas_excluidas_intervalo.csv",
             [{"id": p["id"], "cve_id": p["cve_id"], "activo_id": p["activo_id"], "dia_local": p["dia_local"],
               "ingesta_utc": p["fecha_ingesta_pipeline"].isoformat(sep=" ", timespec="seconds"),
               "cierre_utc": p["fecha_alerta_generada"].isoformat(sep=" ", timespec="seconds"),
               "segundos": round(p["seg"], 1), "motivo": "corrida reparada nodo por nodo el 3/09 (el intervalo mide la reparacion)"}
              for p in camp if p["grupo_intervalo"] == "excluida_reparada_a_mano"])
    cifra("filas excluidas del intervalo: pares que siguen en el resto de las mediciones", len(rep), "pares", "campana", "dia local de la ingesta = 3/09", linea())


# ---------------------------------------------------------------------------------------------
# 5. Volumen de hallazgos y notificaciones, y rendimiento por corrida efectiva
# ---------------------------------------------------------------------------------------------

def seccion_volumen(pares, audit):
    camp = [p for p in pares if p["campana"]]
    pares_por_ingesta = defaultdict(list)
    for p in camp:
        pares_por_ingesta[p["fecha_ingesta_pipeline"]].append(p)

    # Cada fila de auditoria se une con la marca de ingesta de la corrida: la auditoria se escribe al final de
    # la corrida, la ingesta se estampa al empezar la correlacion, a menos de una hora antes.
    previo, filas = None, []
    for r in audit:
        efectiva = previo is None or r["dia_local"] != previo
        previo = r["dia_local"]
        propios = [p for ing, g in pares_por_ingesta.items() if r["ts"] - timedelta(hours=1) <= ing <= r["ts"] for p in g]
        incoherente = r["correlacionados"] == 0 and len(propios) > 0
        filas.append({"fila_auditoria": r["id"], "dia_local": r["dia_local"], "corrida_efectiva": int(efectiva),
                      "vulnerabilidades_ingeridas": r["ingeridos"], "vulnerabilidades_correlacionadas": r["correlacionados"],
                      "pares_nuevos_persistidos": len(propios),
                      "notificaciones": sum(p["estado"] == "NOTIFICADA" for p in propios),
                      "auditoria_contradice_telemetria": int(incoherente)})
    escribir("t5_volumen_por_corrida.csv", filas)
    efect = [f for f in filas if f["corrida_efectiva"]]
    cifra("corridas efectivas con pares nuevos persistidos", sum(f["pares_nuevos_persistidos"] > 0 for f in efect), "corridas efectivas", "campana", "telemetria_vulnerabilidades por marca de ingesta", linea())
    cifra("corridas efectivas sin pares nuevos", sum(f["pares_nuevos_persistidos"] == 0 for f in efect), "corridas efectivas", "campana", "telemetria_vulnerabilidades por marca de ingesta", linea())
    cifra("filas de auditoria que declaran cero correlacionados pese a pares persistidos esa corrida", sum(f["auditoria_contradice_telemetria"] for f in filas), "filas de auditoria", "campana", "auditoria_acciones vs telemetria", linea())
    cifra("pares persistidos por corrida efectiva: media", round(statistics.mean(f["pares_nuevos_persistidos"] for f in efect), 1), "pares por corrida efectiva", "corridas efectivas", "telemetria_vulnerabilidades", linea())
    cifra("pares persistidos por corrida efectiva: mediana", statistics.median(f["pares_nuevos_persistidos"] for f in efect), "pares por corrida efectiva", "corridas efectivas", "telemetria_vulnerabilidades", linea())
    cifra("pares persistidos por corrida efectiva: maximo", max(f["pares_nuevos_persistidos"] for f in efect), "pares por corrida efectiva", "corridas efectivas", "telemetria_vulnerabilidades", linea())
    cifra("ingestas totales sumadas sobre corridas (ventanas superpuestas, no es cobertura)", sum(f["vulnerabilidades_ingeridas"] for f in efect), "vulnerabilidades, con repeticion", "corridas efectivas", "auditoria_acciones.cve_ingeridos", linea())

    # Notificaciones: pares, por estado, por via y por activo.
    estados = Counter(p["estado"] for p in camp)
    cifra("pares persistidos", len(camp), "pares", "campana", "telemetria_vulnerabilidades", linea())
    cifra("notificaciones emitidas", estados["NOTIFICADA"], "pares", "campana", "telemetria_vulnerabilidades.estado", linea())
    cifra("pares informativos", estados["INFORMATIVA"], "pares", "campana", "telemetria_vulnerabilidades.estado", linea())
    cifra("proporcion de pares notificados", pct(estados["NOTIFICADA"], len(camp)), "% de pares", "campana", "telemetria_vulnerabilidades.estado", linea())
    notif = [p for p in camp if p["estado"] == "NOTIFICADA"]
    cifra("notificaciones: vulnerabilidades distintas", len({p["cve_id"] for p in notif}), "vulnerabilidades distintas", "campana", "telemetria_vulnerabilidades.estado", linea())
    cifra("notificaciones: activos distintos", len({p["activo_id"] for p in notif}), "activos", "campana", "telemetria_vulnerabilidades.estado", linea())
    vias = Counter((p["fuente_correlacion"], p["estado"]) for p in camp)
    escribir("t5_volumen_por_via.csv",
             [{"via": v, "pares": sum(c for (a, _), c in vias.items() if a == v),
               "notificadas": vias.get((v, "NOTIFICADA"), 0), "informativas": vias.get((v, "INFORMATIVA"), 0)}
              for v in ("NVD", "HEURISTICA")])
    for v in ("NVD", "HEURISTICA"):
        cifra(f"notificaciones por la via {v}", vias.get((v, "NOTIFICADA"), 0), "pares", "campana", "telemetria_vulnerabilidades", linea())
        cifra(f"pares por la via {v}", sum(c for (a, _), c in vias.items() if a == v), "pares", "campana", "telemetria_vulnerabilidades", linea())

    fig, (a1, a2) = plt.subplots(2, 1, figsize=(10, 5.4), sharex=True)
    xs = range(len(efect))
    a1.bar(xs, [f["pares_nuevos_persistidos"] for f in efect], color="#2b6c8f")
    a1.set_yscale("symlog")
    a1.set_ylabel("Pares nuevos persistidos")
    rotulo(a1, "Panel A")
    a2.bar(xs, [f["notificaciones"] for f in efect], color="#b0443c")
    a2.set_ylabel("Notificaciones")
    a2.set_xticks(list(xs))
    a2.set_xticklabels([f["dia_local"][5:] for f in efect], rotation=70, fontsize=7)
    a2.set_xlabel("Corrida efectiva (fecha local)")
    rotulo(a2, "Panel B")
    guardar_figura(fig, "fig5_volumen_por_corrida.png")


# ---------------------------------------------------------------------------------------------
# 6. Reparto de correlaciones por activo y concentracion
# ---------------------------------------------------------------------------------------------

def seccion_concentracion(pares, activos):
    camp = [p for p in pares if p["campana"]]
    n = len(camp)
    cuenta = Counter(p["activo_id"] for p in camp)
    notif = Counter(p["activo_id"] for p in camp if p["estado"] == "NOTIFICADA")
    orden = sorted(activos, key=lambda a: -cuenta.get(a, 0))
    acum, filas = 0, []
    for aid in orden:
        acum += cuenta.get(aid, 0)
        filas.append({"activo_id": aid, "hostname": activos[aid]["hostname"], "criticidad": int(activos[aid]["criticidad_id"]),
                      "expuesto": int(activos[aid]["exp"]), "pares": cuenta.get(aid, 0), "pct_de_pares": pct(cuenta.get(aid, 0), n),
                      "pct_acumulado": pct(acum, n), "notificaciones": notif.get(aid, 0)})
    escribir("t5_reparto_por_activo.csv", filas)
    xs = sorted(cuenta.values(), reverse=True)
    hhi = sum((x / n) ** 2 for x in cuenta.values())
    # Gini sobre los 30 activos (incluye los que no recibieron ningun par).
    v = sorted(cuenta.get(a, 0) for a in activos)
    gini = sum((2 * (i + 1) - len(v) - 1) * x for i, x in enumerate(v)) / (len(v) * sum(v))
    cifra("activos con al menos un par", len(cuenta), "activos", "campana", "telemetria_vulnerabilidades.activo_id", linea())
    cifra("activos sin ningun par", len(activos) - len(cuenta), "activos", "campana", "telemetria_vulnerabilidades.activo_id", linea())
    for k in (1, 2, 4, 6):
        cifra(f"participacion de los {k} activos con mas pares", pct(sum(xs[:k]), n), "% de pares", "campana", "telemetria_vulnerabilidades.activo_id", linea())
    cifra("indice de Herfindahl-Hirschman del reparto de pares por activo", round(hhi, 3), "indice [0,1]", "campana", "telemetria_vulnerabilidades.activo_id", linea())
    cifra("coeficiente de Gini del reparto de pares por activo", round(gini, 3), "coeficiente [0,1], sobre 30 activos", "campana", "telemetria_vulnerabilidades.activo_id", linea())

    # Activos por vulnerabilidad: una misma vulnerabilidad que alcanza a varios activos genera varios pares.
    por_cve = Counter(p["cve_id"] for p in camp)
    dist = Counter(por_cve.values())
    escribir("t5_activos_por_vulnerabilidad.csv", [{"activos_alcanzados": k, "vulnerabilidades": c} for k, c in sorted(dist.items())])
    cifra("vulnerabilidades distintas con par persistido", len(por_cve), "vulnerabilidades distintas", "campana", "telemetria_vulnerabilidades.cve_id", linea())
    cifra("pares por vulnerabilidad: maximo", max(por_cve.values()), "pares por vulnerabilidad", "campana", "telemetria_vulnerabilidades", linea())
    cifra("vulnerabilidades que alcanzan a un solo activo", dist[1], "vulnerabilidades distintas", "campana", "telemetria_vulnerabilidades", linea())

    fig, ax = plt.subplots(figsize=(9, 4))
    ax.bar(range(len(orden)), [cuenta.get(a, 0) for a in orden], color="#2b6c8f")
    ax.set_yscale("symlog")
    ax.set_xticks(range(len(orden)))
    ax.set_xticklabels([activos[a]["hostname"] for a in orden], rotation=75, ha="right", fontsize=7)
    ax.set_ylabel("Pares persistidos (escala logarítmica)")
    guardar_figura(fig, "fig5_reparto_por_activo.png")


# ---------------------------------------------------------------------------------------------

def main():
    pares, audit, activos = cargar()
    assert sum(p["campana"] for p in pares) == 3848 and len(pares) == 3883, "el universo no coincide con el Anexo D"
    assert len(audit) == 28, "la recoleccion tiene 28 filas de auditoria"
    inventario = leer_csv(RAW / "activos_inventario.csv")
    activos_cpe = {int(a["activo_id"]): claves_cpe(a["cpe"]) for a in inventario}
    estado, meta = foto_nvd(activos_cpe)
    nombre_activo = {int(a["activo_id"]): a["hostname"] for a in inventario}

    cifra("pares de la tabla de telemetria", len(pares), "pares", "total", "telemetria_vulnerabilidades", linea())
    cifra("foto de la NVD usada para el cierre (UTC)", meta["consulta_utc"], "instante", "foto NVD", "meta_configs_vulnerable_*.json", linea())

    seccion_cobertura(pares, audit, activos, estado, nombre_activo)
    seccion_indice(pares)
    seccion_contraste(pares)
    seccion_intervalos(pares, audit)
    seccion_volumen(pares, audit)
    seccion_concentracion(pares, activos)

    escribir("cifras_capitulo5.csv", CIFRAS)
    print(f"{len(CIFRAS)} cifras registradas en paper/tables/cifras_capitulo5.csv")
    for c in CIFRAS:
        print(f"{c['cifra']} = {c['valor']} [{c['unidad_de_computo']}] ({c['script']})")


if __name__ == "__main__":
    main()
