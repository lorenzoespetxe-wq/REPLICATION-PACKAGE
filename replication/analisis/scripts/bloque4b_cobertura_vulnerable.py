"""Bloque 4B -- Cobertura y contraste de la inferencia con y sin coincidencias solo de plataforma.

Sobre una misma foto de la NVD (scripts/bloque4b_reconsulta_vulnerable.py) aplica dos reglas
de coincidencia formal y compara:
  ARTEFACTO   la del nodo `Parse NVD Response`: todo identificador del bloque de
              configuraciones, sin mirar la marca `vulnerable` (igual que el bloque 1).
  VULNERABLE  solo los identificadores con `vulnerable=true`: el producto afectado, no la
              plataforma sobre la que corre.
Usar la misma foto para las dos reglas aisla el efecto de la marca del efecto de los dias
que pasaron entre una consulta y otra.

Mide tres cosas:
  1. Cobertura por vulnerabilidad distinta: cuantas tienen coincidencia formal sobre algun
     activo y cuantas de esas detecto alguna corrida (lista `ids` de la auditoria). Se excluyen
     las publicadas despues de la ultima corrida, que ninguna ventana pudo ver.
  2. Pares formales persistidos en la campana: cuantos coinciden solo como plataforma.
  3. Contraste de los pares inferidos de campana contra el dato formal.

Entradas: data/raw/corridas_campana.csv, data/raw/activos_inventario.csv,
data/raw/nvd_reconsulta/configs_vulnerable_*.csv y su meta, y la base (solo lectura).
Salidas en data/cleaned/bloque4b_cobertura_vulnerable/ (sin titulos ni notas).
"""
import csv
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bloque1_cobertura_cierre import claves_cpe, leer_csv  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
RAW = RAIZ / "data" / "raw"
SALIDA = RAIZ / "data" / "cleaned" / "bloque4b_cobertura_vulnerable"
REGLAS = ("artefacto", "vulnerable")


def pares_de_la_base():
    sql = ("SELECT cve_id, activo_id, fuente_correlacion, coalesce(fuente_correlacion_final,'') "
           "FROM telemetria_vulnerabilidades WHERE fecha_ingesta_pipeline >= '2026-08-30';")
    cmd = ["docker", "exec", "postgres_db", "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -At -F "," -c "{sql}"']
    texto = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return [(c, int(a), f, ff) for c, a, f, ff in (l.split(",") for l in texto.strip().splitlines())]


def coinciden(cpes, activos):
    claves = {k for c in cpes.split() for k in claves_cpe(c)}
    return {aid for aid, ks in activos.items() if any(k in claves for k in ks)}


def main():
    corridas = leer_csv(RAW / "corridas_campana.csv")
    inventario = leer_csv(RAW / "activos_inventario.csv")
    activos = {int(a["activo_id"]): claves_cpe(a["cpe"]) for a in inventario}
    nombre = {int(a["activo_id"]): a["hostname"] for a in inventario}
    ruta = sorted((RAW / "nvd_reconsulta").glob("configs_vulnerable_*.csv"))[-1]
    meta = json.loads(sorted((RAW / "nvd_reconsulta").glob("meta_configs_vulnerable_*.json"))[-1]
                      .read_text(encoding="utf-8"))
    ultima = max(r["ts_utc"] for r in corridas)

    estado = {}
    for c in leer_csv(ruta):
        vuln = coinciden(c["cpes_vulnerables"], activos)
        plat = coinciden(c["cpes_plataforma"], activos)
        estado[c["cve_id"]] = {"pub": c["published"], "status": c["vuln_status"],
                               "con_config": int(c["n_configs"]) > 0,
                               "artefacto": vuln | plat, "vulnerable": vuln}
    visibles = {k for k, v in estado.items() if v["pub"] <= ultima}
    detectados = {i for r in corridas for i in r["ids"].split()}

    # ---- 1. cobertura por vulnerabilidad distinta ----
    cobertura, nunca_filas = [], []
    for regla in REGLAS:
        formal = {k for k in visibles if estado[k][regla]}
        nunca = formal - detectados
        cobertura.append({"regla": regla, "formal_sobre_activo": len(formal),
                          "detectadas": len(formal & detectados), "nunca_detectadas": len(nunca),
                          "cobertura_pct": round(100 * len(formal & detectados) / len(formal), 1),
                          "detectadas_sin_formal": len(detectados - formal)})
        for k in sorted(nunca):
            nunca_filas.append({"regla": regla, "cve_id": k,
                                "activos": " ".join(nombre[a] for a in sorted(estado[k][regla])),
                                "solo_plataforma": not estado[k]["vulnerable"]})

    # ---- 2. pares formales persistidos: cuantos coinciden solo como plataforma ----
    base = pares_de_la_base()
    persistidos = []
    for etiqueta, filtro in (("formal_al_detectar", lambda f, ff: f == "NVD"),
                             ("promovidos", lambda f, ff: f == "HEURISTICA" and ff == "NVD")):
        g = [(c, a) for c, a, f, ff in base if filtro(f, ff)]
        cuenta = Counter("vulnerable" if a in estado.get(c, {}).get("vulnerable", set())
                         else "solo_plataforma" if a in estado.get(c, {}).get("artefacto", set())
                         else "sin_coincidencia_hoy" for c, a in g)
        persistidos.append({"grupo": etiqueta, "pares": len(g), **{k: cuenta.get(k, 0) for k in
                            ("vulnerable", "solo_plataforma", "sin_coincidencia_hoy")},
                            "cves": len({c for c, _ in g})})

    # ---- 3. contraste de los pares inferidos de campana ----
    inferidos = [(c, a) for c, a, f, _ in base if f == "HEURISTICA"]
    contraste = []
    for regla in REGLAS:
        cuenta = Counter()
        for c, a in inferidos:
            e = estado.get(c)
            if e is None:
                cuenta["ausente_en_la_fuente"] += 1
            elif a in e[regla]:
                cuenta["activo_enumerado"] += 1
            elif e["con_config"]:
                cuenta["posible_falso_positivo"] += 1
            else:
                cuenta["sin_configuracion"] += 1
        contraste.append({"regla": regla, "pares_inferidos": len(inferidos), **cuenta})
    fw = [a for a, n in nombre.items() if n == "fw-edge-01"][0]
    fw_detalle = [{"cve_id": c, "artefacto": fw in estado[c]["artefacto"],
                   "vulnerable": fw in estado[c]["vulnerable"], "status": estado[c]["status"]}
                  for c, a in inferidos if a == fw and c in estado]

    SALIDA.mkdir(parents=True, exist_ok=True)
    for archivo, datos in (("cobertura.csv", cobertura), ("nunca_detectadas.csv", nunca_filas),
                           ("persistidos_formales.csv", persistidos),
                           ("contraste_inferencia.csv", contraste), ("fw_edge_01.csv", fw_detalle)):
        campos = list(dict.fromkeys(k for d in datos for k in d))
        with (SALIDA / archivo).open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=campos, restval=0)
            w.writeheader()
            w.writerows(datos)

    print(f"Foto NVD {meta['consulta_utc']} | CVE {len(estado)} | visibles {len(visibles)} | "
          f"detectados {len(detectados)} | pares de campana {len(base)}")
    for titulo, datos in (("COBERTURA", cobertura), ("PERSISTIDOS", persistidos),
                          ("CONTRASTE", contraste), ("FW-EDGE-01", fw_detalle)):
        print(f"\n{titulo}")
        for d in datos:
            print(d)
    print("\nNUNCA DETECTADAS (regla vulnerable)")
    for d in nunca_filas:
        if d["regla"] == "vulnerable":
            print(d)


if __name__ == "__main__":
    main()
