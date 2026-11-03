"""Bloque 12 -- Origen de la severidad de cierre de las vulnerabilidades ingeridas sin puntaje.

Pregunta: para los pares vulnerabilidad-activo que el flujo ingirio sin severidad (cvss_score = 0,
valor que el flujo usa para "sin puntaje"), quien aporto la severidad que aparece despues en
cvss_score_final, escrita por la reevaluacion diferida del 1 de octubre de 2026.

Mecanismo que se reconstruye: el nodo "Extraer CVSS SSVC y KEV" del flujo de reevaluacion
diferida (paper/replication/n8n_workflows/Workflow de Reevaluación Diferida 1.1.json) toma el
PRIMER elemento de metrics.cvssMetricV31, luego V30, V40 y V2 del registro de la API 2.0 de la
NVD, sin mirar la fuente (`source`) ni el tipo (Primary/Secondary) de ese elemento.

Unidad de computo: vulnerabilidad (cve_id distinto) para la clasificacion; los conteos se dan
tambien en pares, asignando a cada par el origen de su vulnerabilidad.

Pasos:
  1. Base (solo lectura): por cve_id con cvss_score = 0, pares, fecha de publicacion, primera
     ingesta (UTC), dia de corrida (fecha local, UTC-3, como en bloque8) y cvss_score_final.
  2. Instantanea local de la CVE List v5 (data/raw/cvelistv5_cierre, etiqueta
     cve_2026-09-27_at_end_of_day, anterior a la reevaluacion): si el contenedor CNA trae alguna
     metrica CVSS; si algun contenedor ADP trae metrica CVSS, su baseScore (misma cascada de
     versiones que el flujo: 3.1, 3.0, 4.0, 2.0) y su providerMetadata.dateUpdated.
     coincide_adp = baseScore ADP == cvss_score_final.
  3. Para las vulnerabilidades sin coincidencia exacta con el ADP, consulta a la API 2.0 de la
     NVD (una peticion por cve_id) y registra la primera metrica de la cascada del flujo (source,
     type, baseScore) y todas las demas metricas CVSS presentes. Las respuestas crudas se guardan
     en data/raw/nvd_origen_severidad/ con un meta JSON que registra la hora UTC de cada consulta.
     Si la respuesta ya esta guardada, se reutiliza (no se vuelve a consultar) salvo --reconsultar.

Regla de clasificacion del origen de la severidad de cierre (por vulnerabilidad):
  - cvss_score_final == 0                              -> "sin severidad al cierre"
  - coincide_adp (instantanea)                         -> "CISA-ADP (coincide)"  [coincidencia de
    valor, no prueba de procedencia: la NVD no se consulto para estas]
  - si no, segun la primera metrica de la cascada en la respuesta actual de la NVD, solo si su
    baseScore == cvss_score_final:
        source == nvd@nist.gov                         -> "NIST (Primary)" (se registra el type)
        source == orgId del CNA (instantanea) o
          source no NIST/ADP con type Secondary y el CNA trae CVSS en la instantanea -> "CNA"
        source == orgId del contenedor ADP CISA-ADP    -> "CISA-ADP (segun NVD)"
        cualquier otra fuente                          -> "otro"
  - si la primera metrica actual de la NVD no reproduce cvss_score_final -> "no determinable"
El identificador de la fuente CISA-ADP en la NVD no se supone: se toma del orgId del contenedor
ADP de la instantanea y se reporta si la NVD lo usa.

Advertencia: providerMetadata.dateUpdated es la ULTIMA modificacion del contenedor ADP, no la
primera; que sea posterior a la ingesta no prueba que el puntaje ADP no existiera al ingerir.

Agregado (12/10): avisos agrupados. Las vulnerabilidades sin severidad se agrupan por quien las
publico (providerMetadata.shortName del contenedor CNA) y por el minuto de publicacion (un aviso
agrupado publica sus registros con milisegundos de diferencia); para cada grupo se cuentan, en la
base, todas las vulnerabilidades publicadas en ese mismo minuto y
cuantas de ellas llegaron sin severidad (salida: avisos_agrupados.csv).

Agregado (12/10): severidad al ingerir. Para cada una de las vulnerabilidades sin severidad se lee,
del historial de ejecuciones del orquestador (base interna de n8n, solo lectura; mismo metodo que
bloque1_estado_al_ingerir.py), lo que devolvio la NVD en la corrida de su ingesta, y se registra si
el registro traia alguna metrica CVSS en ese momento. Un cero verdadero seria una metrica presente
con baseScore 0; un cero por ausencia, la falta de metrica.

Entradas: base de datos (solo lectura), historial del orquestador, data/raw/cvelistv5_cierre/, API 2.0 de la NVD.
Salidas (data/cleaned/bloque12_origen_severidad/): detalle_por_vulnerabilidad.csv, resumen.csv
Respuestas crudas: data/raw/nvd_origen_severidad/<CVE>.json y meta_consultas.json

Uso (desde la raiz del proyecto; la clave es opcional y solo se lee del entorno):
    python scripts/bloque12_origen_severidad.py [--reconsultar]
"""
import argparse
import csv
import io
import json
import os
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
import importlib.util

RAIZ = Path(__file__).resolve().parent.parent
CORPUS = RAIZ / "data" / "raw" / "cvelistv5_cierre" / "cves"
CRUDO = RAIZ / "data" / "raw" / "nvd_origen_severidad"
SALIDA = RAIZ / "data" / "cleaned" / "bloque12_origen_severidad"
CONTENEDOR = "postgres_db"
CORRIDAS = RAIZ / "data" / "raw" / "corridas_campana.csv"
_spec = importlib.util.spec_from_file_location("b1", RAIZ / "scripts" / "bloque1_estado_al_ingerir.py")
B1 = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(B1)  # reutiliza psql, decodificar y vulnerabilidades del bloque 1
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
REINTENTOS = 6
HUSO_LOCAL = timedelta(hours=-3)  # mismo criterio que bloque8 para el dia de corrida
NIST = "nvd@nist.gov"
CASCADA_NVD = ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2")
CASCADA_V5 = ("cvssV3_1", "cvssV3_0", "cvssV4_0", "cvssV2_0")
ORIGENES = ("CISA-ADP (coincide)", "NIST (Primary)", "CNA", "CISA-ADP (segun NVD)", "otro",
            "no determinable", "sin severidad al cierre")
COLUMNAS = ["cve_id", "pares", "fecha_publicacion_nvd", "primera_ingesta_utc", "dia_corrida",
            "cvss_score_final", "cna_nombre", "cna_tiene_cvss", "adp_nombre", "adp_tiene_cvss", "adp_base_score",
            "adp_fecha_actualizacion", "adp_actualizado_despues_de_ingesta", "coincide_adp",
            "nvd_consultada", "nvd_primera_fuente", "nvd_primera_tipo", "nvd_primera_version",
            "nvd_primera_score", "nvd_otras_metricas", "origen"]


def leer_base():
    sql = ("COPY (select cve_id, count(*) as pares, min(fecha_publicacion_nvd) as fecha_publicacion_nvd, "
           "min(fecha_ingesta_pipeline) as primera_ingesta, min(cvss_score_final) as cvss_min, "
           "max(cvss_score_final) as cvss_max from telemetria_vulnerabilidades where cvss_score = 0 "
           "group by cve_id order by cve_id) TO STDOUT WITH CSV HEADER")
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c", f'psql -U "$POSTGRES_USER" -d secops_research_db -c "{sql}"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return list(csv.DictReader(io.StringIO(texto)))


def leer_instantes():
    """Por minuto de publicacion (UTC): vulnerabilidades distintas en la base y cuantas llegaron sin severidad."""
    sql = ("COPY (select to_char(fecha_publicacion_nvd, 'YYYY-MM-DD HH24:MI') as minuto, count(distinct cve_id) as vulnerabilidades, "
           "count(distinct cve_id) filter (where cvss_score = 0) as sin_severidad, count(*) as pares "
           "from telemetria_vulnerabilidades group by 1) TO STDOUT WITH CSV HEADER")
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c", f'psql -U "$POSTGRES_USER" -d secops_research_db -c "{sql}"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return {r["minuto"]: r for r in csv.DictReader(io.StringIO(texto))}


def leer_primer_dia(minutos_excluidos):
    """Pares ingeridos a menos de 24 horas de su publicacion, fuera de los avisos agrupados dados."""
    lista = ",".join(f"'{m}'" for m in minutos_excluidos)
    sql = ("COPY (select count(*) as pares, count(*) filter (where cvss_score = 0) as sin_severidad, "
           "round(min(extract(epoch from fecha_ingesta_pipeline - fecha_publicacion_nvd)/3600)::numeric, 1) as horas_min, "
           "round(max(extract(epoch from fecha_ingesta_pipeline - fecha_publicacion_nvd)/3600)::numeric, 1) as horas_max "
           "from telemetria_vulnerabilidades where fecha_ingesta_pipeline - fecha_publicacion_nvd < interval '24 hours' "
           f"and to_char(fecha_publicacion_nvd, 'YYYY-MM-DD HH24:MI') not in ({lista})) TO STDOUT WITH CSV HEADER")
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c", f'psql -U "$POSTGRES_USER" -d secops_research_db -c "{sql}"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return next(csv.DictReader(io.StringIO(texto)))


def ruta_registro(cve_id):
    _, anio, num = cve_id.split("-")
    return CORPUS / anio / f"{int(num) // 1000}xxx" / f"{cve_id}.json"


def score_v5(metricas):
    """Primer baseScore en la cascada 3.1, 3.0, 4.0, 2.0 dentro de una lista de metricas v5."""
    for clave in CASCADA_V5:
        for m in metricas:
            if clave in m and m[clave].get("baseScore") is not None:
                return float(m[clave]["baseScore"])
    return None


def leer_v5(cve_id):
    ruta = ruta_registro(cve_id)
    if not ruta.exists():
        return {"existe": False}
    reg = json.loads(ruta.read_text(encoding="utf-8"))
    cna = reg["containers"]["cna"]
    adps = reg["containers"].get("adp", [])
    con_cvss = [a for a in adps if score_v5(a.get("metrics", [])) is not None]
    adp = con_cvss[0] if con_cvss else (next((a for a in adps if a["providerMetadata"].get("shortName") == "CISA-ADP"), None))
    return {"existe": True,
            "cna_org": cna["providerMetadata"].get("orgId", ""),
            "cna_nombre": cna["providerMetadata"].get("shortName", ""),
            "cna_tiene_cvss": score_v5(cna.get("metrics", [])) is not None,
            "adp_nombre": adp["providerMetadata"].get("shortName", "") if adp else "",
            "adp_org": adp["providerMetadata"].get("orgId", "") if adp else "",
            "adp_score": score_v5(adp.get("metrics", [])) if adp else None,
            "adp_fecha": adp["providerMetadata"].get("dateUpdated", "") if adp else "",
            "adps_con_cvss": len(con_cvss)}


def pedir(cve_id, clave):
    """Una peticion a la NVD con reintentos ante limite de ritmo (patron de bloque1_reconsulta_nvd)."""
    url = f"{URL}?{urllib.parse.urlencode({'cveId': cve_id})}"
    cabeceras = {"User-Agent": "PoC_Tesis_SecOps/1.0 (origen de severidad)", "Accept": "application/json"}
    if clave:
        cabeceras["apiKey"] = clave
    for intento in range(1, REINTENTOS + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=cabeceras), timeout=120) as r:
                return json.load(r)
        except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError) as e:
            codigo = getattr(e, "code", None)
            if codigo in (400, 401, 404):
                raise SystemExit(f"Error {codigo} de la NVD para {cve_id}.")
            espera = 10 * intento
            print(f"  {cve_id}: intento {intento} fallo ({codigo or e}); espero {espera} s", flush=True)
            time.sleep(espera)
    raise SystemExit("La NVD no respondio tras los reintentos.")


def metricas_nvd(cuerpo):
    """Lista (version, source, type, baseScore) en el orden de la cascada del flujo."""
    vulns = cuerpo.get("vulnerabilities", [])
    if not vulns:
        return []
    m = vulns[0]["cve"].get("metrics", {})
    return [(v, x.get("source", ""), x.get("type", ""), float(x["cvssData"]["baseScore"]))
            for v in CASCADA_NVD for x in m.get(v, [])]


def clasificar(final, v5, coincide, primera, adp_org):
    if final == 0:
        return "sin severidad al cierre"
    if coincide:
        return "CISA-ADP (coincide)"
    if primera is None or primera[3] != final:
        return "no determinable"
    _, fuente, tipo, _ = primera
    if fuente == NIST:
        return "NIST (Primary)" if tipo == "Primary" else "otro"
    if adp_org and fuente == adp_org:
        return "CISA-ADP (segun NVD)"
    if fuente == v5.get("cna_org") or (tipo == "Secondary" and v5.get("cna_tiene_cvss")):
        return "CNA"
    return "otro"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reconsultar", action="store_true", help="ignora respuestas NVD ya guardadas")
    args = ap.parse_args()
    clave = os.environ.get("NVD_API_KEY", "")
    pausa = 1 if clave else 6.5

    base = leer_base()
    detalle = []
    for b in base:
        assert b["cvss_min"] == b["cvss_max"], f"{b['cve_id']}: cvss_score_final distinto entre pares"
        ingesta = datetime.fromisoformat(b["primera_ingesta"])
        v5 = leer_v5(b["cve_id"])
        final = float(b["cvss_min"])
        adp_fecha = v5.get("adp_fecha", "")
        despues = ""
        if adp_fecha:
            despues = datetime.fromisoformat(adp_fecha.replace("Z", "+00:00")).replace(tzinfo=None) > ingesta
        detalle.append({"cve_id": b["cve_id"], "pares": int(b["pares"]),
                        "fecha_publicacion_nvd": b["fecha_publicacion_nvd"],
                        "primera_ingesta_utc": b["primera_ingesta"],
                        "dia_corrida": (ingesta + HUSO_LOCAL).date().isoformat(),
                        "cvss_score_final": final, "_v5": v5,
                        "cna_nombre": v5.get("cna_nombre", ""),
                        "cna_tiene_cvss": v5.get("cna_tiene_cvss", ""), "adp_nombre": v5.get("adp_nombre", ""),
                        "adp_tiene_cvss": v5.get("adp_score") is not None, "adp_base_score": v5.get("adp_score"),
                        "adp_fecha_actualizacion": adp_fecha, "adp_actualizado_despues_de_ingesta": despues,
                        "coincide_adp": v5.get("adp_score") is not None and v5["adp_score"] == final})

    # consulta a la NVD solo para las que no coinciden con el ADP
    CRUDO.mkdir(parents=True, exist_ok=True)
    ruta_meta = CRUDO / "meta_consultas.json"
    meta = json.loads(ruta_meta.read_text(encoding="utf-8")) if ruta_meta.exists() else {"consultas": {}}
    a_consultar = [d for d in detalle if not d["coincide_adp"] and d["cvss_score_final"] != 0]
    for i, d in enumerate(a_consultar):
        ruta = CRUDO / f"{d['cve_id']}.json"
        if ruta.exists() and not args.reconsultar:
            continue
        if i:
            time.sleep(pausa)
        cuerpo = pedir(d["cve_id"], clave)
        ruta.write_text(json.dumps(cuerpo, indent=1), encoding="utf-8")
        meta["consultas"][d["cve_id"]] = {"consulta_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                                          "con_clave": bool(clave), "url": f"{URL}?cveId={d['cve_id']}"}
        print(f"  consultada {d['cve_id']}", flush=True)
    ruta_meta.write_text(json.dumps(meta, indent=1), encoding="utf-8")

    fuentes_adp_en_nvd = Counter()
    for d in detalle:
        v5 = d["_v5"]
        primera = None
        d["nvd_consultada"] = d in a_consultar
        if d["nvd_consultada"]:
            ms = metricas_nvd(json.loads((CRUDO / f"{d['cve_id']}.json").read_text(encoding="utf-8")))
            primera = ms[0] if ms else None
            d["nvd_otras_metricas"] = " | ".join(f"{v}:{s}:{t}:{x}" for v, s, t, x in ms[1:])
            fuentes_adp_en_nvd.update(s for _, s, _, _ in ms if v5.get("adp_org") and s == v5["adp_org"])
        d["nvd_primera_version"], d["nvd_primera_fuente"], d["nvd_primera_tipo"], d["nvd_primera_score"] = (
            primera if primera else ("", "", "", ""))
        d.setdefault("nvd_otras_metricas", "")
        d["origen"] = clasificar(d["cvss_score_final"], v5, d["coincide_adp"], primera, v5.get("adp_org"))

    res = []

    def reg(medida, unidad, valor):
        res.append((medida, unidad, valor))

    reg("pares ingeridos sin severidad (cvss_score = 0)", "pares", sum(d["pares"] for d in detalle))
    reg("vulnerabilidades distintas ingeridas sin severidad", "vulnerabilidades", len(detalle))
    reg("sin registro en la instantanea CVE List v5", "vulnerabilidades", sum(1 for d in detalle if not d["_v5"]["existe"]))
    reg("CNA con metrica CVSS en la instantanea", "vulnerabilidades", sum(1 for d in detalle if d["cna_tiene_cvss"] is True))
    reg("ADP con metrica CVSS en la instantanea", "vulnerabilidades", sum(1 for d in detalle if d["adp_tiene_cvss"]))
    reg("ADP con metrica CVSS: nombre CISA-ADP", "vulnerabilidades", sum(1 for d in detalle if d["adp_tiene_cvss"] and d["adp_nombre"] == "CISA-ADP"))
    reg("puntaje ADP igual a cvss_score_final", "vulnerabilidades", sum(1 for d in detalle if d["coincide_adp"]))
    reg("consultadas a la NVD (sin coincidencia ADP)", "vulnerabilidades", len(a_consultar))
    reg("metricas NVD con source igual al orgId CISA-ADP de la instantanea", "metricas", sum(fuentes_adp_en_nvd.values()))
    for o in ORIGENES:
        reg(f"origen de la severidad de cierre: {o}", "vulnerabilidades", sum(1 for d in detalle if d["origen"] == o))
    for o in ORIGENES:
        reg(f"origen de la severidad de cierre: {o}", "pares", sum(d["pares"] for d in detalle if d["origen"] == o))
    por_dia = Counter((d["dia_corrida"], d["origen"]) for d in detalle)
    pares_dia = Counter()
    for d in detalle:
        pares_dia[(d["dia_corrida"], d["origen"])] += d["pares"]
    for (dia, o) in sorted(por_dia):
        reg(f"dia de corrida {dia}, origen {o}", "vulnerabilidades", por_dia[(dia, o)])
        reg(f"dia de corrida {dia}, origen {o}", "pares", pares_dia[(dia, o)])
    con_fecha = [d for d in detalle if d["adp_tiene_cvss"]]
    reg("ADP con CVSS: ultima modificacion ADP anterior a la primera ingesta", "vulnerabilidades",
        sum(1 for d in con_fecha if d["adp_actualizado_despues_de_ingesta"] is False))
    reg("ADP con CVSS: ultima modificacion ADP posterior a la primera ingesta (no prueba ausencia al ingerir)",
        "vulnerabilidades", sum(1 for d in con_fecha if d["adp_actualizado_despues_de_ingesta"] is True))
    reg("ADP coincide: ultima modificacion ADP anterior a la primera ingesta", "vulnerabilidades",
        sum(1 for d in con_fecha if d["coincide_adp"] and d["adp_actualizado_despues_de_ingesta"] is False))
    reg("ADP coincide: ultima modificacion ADP posterior a la primera ingesta", "vulnerabilidades",
        sum(1 for d in con_fecha if d["coincide_adp"] and d["adp_actualizado_despues_de_ingesta"] is True))

    # avisos agrupados: quien publico y en que instante
    instantes = leer_instantes()
    grupos = Counter((d["cna_nombre"], d["fecha_publicacion_nvd"][:16]) for d in detalle)
    pares_grupo = Counter()
    for d in detalle:
        pares_grupo[(d["cna_nombre"], d["fecha_publicacion_nvd"][:16])] += d["pares"]
    edades = {}
    for d in detalle:
        h = (datetime.fromisoformat(d["primera_ingesta_utc"]) - datetime.fromisoformat(d["fecha_publicacion_nvd"])).total_seconds() / 3600
        edades.setdefault((d["cna_nombre"], d["fecha_publicacion_nvd"][:16]), []).append(round(h, 1))
    filas_avisos = []
    for (cna_nombre, instante), n in sorted(grupos.items(), key=lambda x: x[0][1]):
        tot = instantes[instante]
        assert int(tot["sin_severidad"]) == n
        filas_avisos.append({"publicado_por": cna_nombre, "minuto_publicacion_utc": instante,
                             "vulnerabilidades_en_la_base": int(tot["vulnerabilidades"]),
                             "pares_en_la_base": int(tot["pares"]),
                             "vulnerabilidades_sin_severidad": n,
                             "pares_sin_severidad": pares_grupo[(cna_nombre, instante)],
                             "horas_publicacion_a_ingesta_min": min(edades[(cna_nombre, instante)]),
                             "horas_publicacion_a_ingesta_max": max(edades[(cna_nombre, instante)])})
    reg("avisos agrupados (quien publico + minuto de publicacion) que reunen las vulnerabilidades sin severidad",
        "avisos", len(filas_avisos))
    assert sum(f["pares_sin_severidad"] for f in filas_avisos) == sum(d["pares"] for d in detalle)
    # severidad al ingerir, segun el historial del orquestador
    corridas = {r["dia_local"]: r["fila_auditoria"] for r in csv.DictReader(open(CORRIDAS, encoding="utf-8"))}
    al_ingerir = {}
    for dia in sorted({d["dia_corrida"] for d in detalle}):
        ejec = B1.psql("secops_research_db",
                       f"SELECT entidad_id FROM auditoria_acciones WHERE id={corridas[dia]};").strip()
        texto = B1.psql("n8n_internal", f'SELECT data FROM execution_data WHERE \\"executionId\\"={ejec};').strip()
        de_este_dia = {d["cve_id"] for d in detalle if d["dia_corrida"] == dia}
        for v in B1.vulnerabilidades(B1.decodificar(texto)):
            if v["cve"]["id"] not in de_este_dia:
                continue  # la ventana de tres dias repite vulnerabilidades: solo cuenta la corrida de su ingesta
            m = v["cve"].get("metrics", {})
            al_ingerir[v["cve"]["id"]] = [float(x["cvssData"]["baseScore"]) for k in CASCADA_NVD for x in m.get(k, [])]
    vistas = [d for d in detalle if d["cve_id"] in al_ingerir]
    reg("sin severidad: vulnerabilidades encontradas en el historial de su corrida de ingesta", "vulnerabilidades", len(vistas))
    reg("sin severidad: sin ninguna metrica CVSS al ingerir (cero por ausencia)", "vulnerabilidades",
        sum(1 for d in vistas if not al_ingerir[d["cve_id"]]))
    reg("sin severidad: con metrica CVSS de puntaje 0 al ingerir (cero verdadero)", "vulnerabilidades",
        sum(1 for d in vistas if al_ingerir[d["cve_id"]] and min(al_ingerir[d["cve_id"]]) == 0))
    reg("puntaje de cierre minimo de las vulnerabilidades sin severidad", "puntaje",
        min(d["cvss_score_final"] for d in detalle))

    otros = leer_primer_dia([f["minuto_publicacion_utc"] for f in filas_avisos])
    reg("fuera de esos avisos: pares ingeridos a menos de 24 horas de la publicacion", "pares", int(otros["pares"]))
    reg("fuera de esos avisos: de ellos, sin severidad", "pares", int(otros["sin_severidad"]))
    reg("fuera de esos avisos: edad minima al ingerir", "horas", float(otros["horas_min"]))
    reg("fuera de esos avisos: edad maxima al ingerir", "horas", float(otros["horas_max"]))

    assert sum(d["pares"] for d in detalle) == sum(v for (m, u, v) in res if u == "pares" and m.startswith("origen"))
    assert len(detalle) == sum(v for (m, u, v) in res if u == "vulnerabilidades" and m.startswith("origen"))

    SALIDA.mkdir(parents=True, exist_ok=True)
    with open(SALIDA / "detalle_por_vulnerabilidad.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=COLUMNAS, extrasaction="ignore")
        w.writeheader()
        w.writerows(detalle)
    with open(SALIDA / "avisos_agrupados.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(filas_avisos[0]))
        w.writeheader()
        w.writerows(filas_avisos)
    with open(SALIDA / "resumen.csv", "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(["medida", "unidad", "valor"])
        w.writerows(res)

    for m, u, v in res:
        print(f"{str(v):>6}  {m}  [{u}]")
    print("\nSin coincidencia ADP:")
    for d in a_consultar:
        print(f"  {d['cve_id']} final={d['cvss_score_final']} adp={d['adp_base_score']} cna_cvss={d['cna_tiene_cvss']} "
              f"| NVD 1a: {d['nvd_primera_version']} {d['nvd_primera_fuente']} {d['nvd_primera_tipo']} "
              f"{d['nvd_primera_score']} | otras: {d['nvd_otras_metricas']} -> {d['origen']}")


if __name__ == "__main__":
    main()
