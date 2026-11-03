"""Bloque 5 -- Sorteo de la muestra de validacion de las dos vias de correlacion del artefacto.

Diseno (declarado antes de sortear, no se modifica despues):
  - Via de inferencia: muestreo estratificado por producto del inventario. Unidad de muestreo =
    caso distinto (vulnerabilidad, producto del activo), porque dos activos con el mismo
    identificador dan la misma respuesta. Total fijo N_MUESTRA; minimo MINIMO_POR_ESTRATO por
    estrato (o todos, si el estrato tiene menos); el resto se reparte en proporcion al tamano del
    estrato (resto mayor). La tasa se pondera despues por el tamano real de cada estrato.
  - Excluidos del sorteo y sumados despues a la tasa total de la via: los casos del firewall
    (Cisco IOS) que ya se sabe que son falsos positivos.
  - Via formal: censo, no muestra. Se revisan todas las vulnerabilidades cuyos pares persistidos
    coinciden con el activo como producto afectado (`vulnerable=true`). Los pares que coinciden
    solo como plataforma son errores seguros frente al inventario y se registran aparte.

Entradas:
  - base de datos (solo lectura)   pares persistidos en telemetria_vulnerabilidades
  - data/raw/activos_inventario.csv
  - data/raw/nvd_reconsulta/configs_vulnerable_*.csv   foto de cierre de la NVD (ultima)
  - data/raw/afectados_al_ingerir.csv                  nombres que el artefacto leyo al ingerir

Salidas (data/cleaned/bloque5_muestra_validacion/, sin titulos ni notas):
  - universo_inferencia.csv, asignacion_inferencia.csv, muestra_inferencia.csv
  - universo_formal.csv, errores_conocidos.csv
  - planilla_revision.csv, registro_sorteo.json
"""
import csv
import hashlib
import json
import math
import random
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bloque1_cobertura_cierre import claves_cpe, leer_csv  # noqa: E402

SEMILLA = 20261004
N_MUESTRA = 65
MINIMO_POR_ESTRATO = 2
PRODUCTO_CONOCIDO_FALSO = "cisco:ios"   # los siete falsos positivos del firewall

RAIZ = Path(__file__).resolve().parent.parent
RAW = RAIZ / "data" / "raw"
SALIDA = RAIZ / "data" / "cleaned" / "bloque5_muestra_validacion"
CONTENEDOR = "postgres_db"

random.seed(SEMILLA)


def pares_de_la_base():
    sql = ("SELECT cve_id, activo_id, fuente_correlacion FROM telemetria_vulnerabilidades "
           "WHERE fuente_correlacion IN ('HEURISTICA','NVD');")
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -At -F "," -c "{sql}"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return [(c, int(a), f) for c, a, f in (l.split(",") for l in texto.strip().splitlines())]


def producto(cpe):
    p = cpe.split(":")
    return f"{p[3]}:{p[4]}"


def coinciden(cpes, activos):
    claves = {k for c in cpes.split() for k in claves_cpe(c)}
    return {aid for aid, ks in activos.items() if any(k in claves for k in ks)}


def reparto(tamanos, total, minimo):
    """Minimo por estrato (o todo el estrato) y el resto proporcional, por resto mayor."""
    base = {h: min(minimo, n) for h, n in tamanos.items()}
    resto = total - sum(base.values())
    capacidad = {h: tamanos[h] - base[h] for h in tamanos}
    suma = sum(capacidad.values())
    crudo = {h: resto * capacidad[h] / suma for h in tamanos}
    extra = {h: min(math.floor(crudo[h]), capacidad[h]) for h in tamanos}
    faltan = resto - sum(extra.values())
    for h in sorted(tamanos, key=lambda k: (-(crudo[k] - math.floor(crudo[k])), k)):
        if faltan == 0:
            break
        if extra[h] < capacidad[h]:
            extra[h] += 1
            faltan -= 1
    return {h: base[h] + extra[h] for h in tamanos}


def escribir(ruta, filas, campos):
    with ruta.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(filas)


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)
    inventario = leer_csv(RAW / "activos_inventario.csv")
    cpe_de = {int(a["activo_id"]): a["cpe"] for a in inventario}
    host_de = {int(a["activo_id"]): a["hostname"] for a in inventario}
    claves = {aid: claves_cpe(c) for aid, c in cpe_de.items()}

    base = pares_de_la_base()

    # ---------- via de inferencia: universo de casos distintos ----------
    casos = defaultdict(list)
    for cve, aid, fuente in base:
        if fuente == "HEURISTICA":
            casos[(cve, producto(cpe_de[aid]))].append(aid)

    leidos = {}
    for r in leer_csv(RAW / "afectados_al_ingerir.csv"):
        leidos.setdefault(r["cve_id"], r["afectados"])

    universo = []
    for (cve, prod), activos in sorted(casos.items()):
        universo.append({"cve_id": cve, "estrato": prod, "pares": len(activos),
                         "activos": " ".join(sorted(host_de[a] for a in activos)),
                         "cpe_inventario": cpe_de[activos[0]], "afectados_al_ingerir": leidos.get(cve, "")})
    campos_u = list(universo[0].keys())
    escribir(SALIDA / "universo_inferencia.csv", universo, campos_u)

    conocidos_inf = [u for u in universo if u["estrato"] == PRODUCTO_CONOCIDO_FALSO]
    sorteable = [u for u in universo if u["estrato"] != PRODUCTO_CONOCIDO_FALSO]
    por_estrato = defaultdict(list)
    for u in sorteable:
        por_estrato[u["estrato"]].append(u)
    tamanos = {h: len(v) for h, v in por_estrato.items()}
    asignado = reparto(tamanos, N_MUESTRA, MINIMO_POR_ESTRATO)

    muestra, asignacion = [], []
    for h in sorted(por_estrato):
        elegidos = random.sample(por_estrato[h], asignado[h])
        elegidos.sort(key=lambda u: u["cve_id"])
        pares_h = sum(u["pares"] for u in por_estrato[h])
        asignacion.append({"estrato": h, "casos_universo": tamanos[h], "pares_universo": pares_h,
                           "casos_muestra": asignado[h],
                           "peso_caso": round(tamanos[h] / asignado[h], 4)})
        for u in elegidos:
            muestra.append({**u, "estrato_n": tamanos[h], "estrato_m": asignado[h],
                            "peso_caso": round(tamanos[h] / asignado[h], 4)})
    escribir(SALIDA / "asignacion_inferencia.csv", asignacion, list(asignacion[0].keys()))
    escribir(SALIDA / "muestra_inferencia.csv", muestra, list(muestra[0].keys()))

    # efecto de diseno (Kish) y margen del peor caso, solo para el registro
    w = [m["peso_caso"] for m in muestra]
    deff = len(w) * sum(x * x for x in w) / sum(w) ** 2
    n_ef = len(w) / deff
    N = len(sorteable)
    margen = 1.96 * math.sqrt(0.25 / n_ef * (1 - n_ef / N))

    # ---------- via formal: censo ----------
    ruta_nvd = sorted((RAW / "nvd_reconsulta").glob("configs_vulnerable_*.csv"))[-1]
    estado = {}
    for c in leer_csv(ruta_nvd):
        estado[c["cve_id"]] = (coinciden(c["cpes_vulnerables"], claves),
                               coinciden(c["cpes_plataforma"], claves), c["vuln_status"])
    formales = defaultdict(list)
    for cve, aid, fuente in base:
        if fuente == "NVD":
            vul, plat, _ = estado.get(cve, (set(), set(), ""))
            clase = ("producto_afectado" if aid in vul else
                     "solo_plataforma" if aid in plat else "sin_coincidencia_hoy")
            formales[(cve, clase)].append(aid)

    universo_f, errores = [], []
    for (cve, clase), activos in sorted(formales.items()):
        fila = {"cve_id": cve, "clase_nvd_hoy": clase, "pares": len(activos),
                "activos": " ".join(sorted(host_de[a] for a in activos)),
                "productos": " ".join(sorted({producto(cpe_de[a]) for a in activos})),
                "estado_nvd": estado.get(cve, (0, 0, ""))[2]}
        universo_f.append(fila)
        if clase != "producto_afectado":
            errores.append({"via": "formal", "motivo": clase, **{k: fila[k] for k in
                            ("cve_id", "pares", "activos", "productos")}})
    for u in conocidos_inf:
        errores.append({"via": "inferencia", "motivo": "falso_positivo_confirmado_firewall",
                        "cve_id": u["cve_id"], "pares": u["pares"], "activos": u["activos"],
                        "productos": u["estrato"]})
    escribir(SALIDA / "universo_formal.csv", universo_f, list(universo_f[0].keys()))
    escribir(SALIDA / "errores_conocidos.csv", errores, list(errores[0].keys()))

    # El censo incluye las filas de estabilizacion que la foto de la NVD no cubre: no hay dato
    # para clasificarlas, asi que se revisan a mano.
    censo = [u for u in universo_f if u["clase_nvd_hoy"] != "solo_plataforma"]

    # ---------- planilla de revision ----------
    planilla = []
    for i, m in enumerate(sorted(muestra, key=lambda m: (m["estrato"], m["cve_id"])), 1):
        planilla.append({"id": f"I{i:02d}", "via": "inferencia", "cve_id": m["cve_id"],
                         "producto_inventario": m["estrato"], "activos": m["activos"],
                         "pares": m["pares"], "nombres_leidos_por_el_artefacto": m["afectados_al_ingerir"]})
    for i, c in enumerate(sorted(censo, key=lambda c: c["cve_id"]), 1):
        planilla.append({"id": f"F{i:02d}", "via": "formal", "cve_id": c["cve_id"],
                         "producto_inventario": c["productos"], "activos": c["activos"],
                         "pares": c["pares"], "nombres_leidos_por_el_artefacto": "",
                         "notas": "fila de estabilizacion, sin dato en la foto de la NVD"
                         if c["clase_nvd_hoy"] == "sin_coincidencia_hoy" else ""})
    campos_p = list(planilla[0].keys()) + [
        "aviso_url", "producto_afectado_segun_aviso", "version_en_rango", "coincidencia_nombres",
        "par_correcto", "tipo_error", "notas"]
    for fila in planilla:
        for c in campos_p:
            fila.setdefault(c, "")
    escribir(SALIDA / "planilla_revision.csv", planilla, campos_p)

    # ---------- registro del sorteo ----------
    huella = hashlib.sha256((SALIDA / "universo_inferencia.csv").read_bytes()).hexdigest()
    registro = {
        "fecha_sorteo": date.today().isoformat(), "semilla": SEMILLA,
        "n_muestra_inferencia": len(muestra), "minimo_por_estrato": MINIMO_POR_ESTRATO,
        "foto_nvd": ruta_nvd.name, "sha256_universo_inferencia": huella,
        "inferencia": {"pares_persistidos": sum(u["pares"] for u in universo),
                       "casos_distintos": len(universo), "vulnerabilidades": len({u["cve_id"] for u in universo}),
                       "casos_conocidos_excluidos": len(conocidos_inf),
                       "pares_conocidos_excluidos": sum(u["pares"] for u in conocidos_inf),
                       "casos_sorteables": N, "estratos": len(tamanos),
                       "efecto_de_diseno": round(deff, 3), "tamano_efectivo": round(n_ef, 1),
                       "margen_peor_caso_95": round(margen, 3)},
        "formal": {"pares_persistidos": sum(u["pares"] for u in universo_f),
                   "por_clase_pares": dict(Counter({k: sum(u["pares"] for u in universo_f if u["clase_nvd_hoy"] == k)
                                                    for k in {u["clase_nvd_hoy"] for u in universo_f}})),
                   "censo_vulnerabilidades": len(censo), "censo_pares": sum(u["pares"] for u in censo),
                   "censo_sin_dato_nvd_vulnerabilidades": sum(1 for u in censo if u["clase_nvd_hoy"] == "sin_coincidencia_hoy")},
        "filas_planilla": len(planilla),
    }
    (SALIDA / "registro_sorteo.json").write_text(json.dumps(registro, indent=2, ensure_ascii=False),
                                                 encoding="utf-8")
    print(json.dumps(registro, indent=2, ensure_ascii=False))
    print()
    for a in asignacion:
        print(f"{a['estrato']:35s} universo {a['casos_universo']:4d}  pares {a['pares_universo']:4d}  muestra {a['casos_muestra']:3d}")


if __name__ == "__main__":
    main()
