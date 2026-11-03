"""Bloque 13 -- Verificacion de las corridas en cero contra la consulta de cierre (seccion 5.5).

Una corrida que no correlaciona nada deja la misma fila de auditoria si el dia fue tranquilo o
si el nodo de correlacion fallo. El criterio de la seccion 3.8 (contradiccion entre un cero y
pares persistidos) descarta solo la segunda posibilidad cuando hubo pares. Este script contrasta
los dias en cero contra una fuente que no depende del codigo del nodo: lo que la NVD vincula con
el inventario en la consulta del 3/10 (apartado 5.1.3).

  1. Dias en cero: corridas efectivas con cero correlacionadas y cero pares persistidos.
  2. Perdidas que pasaron solo por dias en cero: de las vulnerabilidades que la NVD vincula con
     algun activo y que el artefacto nunca detecto, cuantas se ingirieron unicamente en esas
     corridas. Con las dos reglas del apartado 5.1.3.
  3. Detecciones demoradas: de las vulnerabilidades detectadas, cuantas pasaron por un dia en
     cero antes de la corrida que las detecto, por via.

Unidad: vulnerabilidades distintas. Universo: campana.
Entradas: paper/tables/t5_volumen_por_corrida.csv (bloque 8); data/raw/afectados_al_ingerir.csv
(lo que la NVD devolvio en cada corrida, historial del orquestador);
data/cleaned/bloque4b_cobertura_vulnerable/nunca_detectadas.csv (bloque 4B);
data/cleaned/bloque12b_latencia_deteccion/por_vulnerabilidad.csv (bloque 12B).
Salidas (data/cleaned/bloque13_dias_en_cero/): resumen.csv, perdidas_en_dias_cero.csv
"""
import csv
from collections import defaultdict
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "data" / "cleaned" / "bloque13_dias_en_cero"
SALIDA.mkdir(parents=True, exist_ok=True)


def leer(ruta):
    with open(RAIZ / ruta, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


# 1. Dias en cero y corridas efectivas
corridas = leer("paper/tables/t5_volumen_por_corrida.csv")
efectivas = {c["fila_auditoria"]: c["dia_local"] for c in corridas if c["corrida_efectiva"] == "1"}
cero = {
    c["fila_auditoria"]: c["dia_local"]
    for c in corridas
    if c["corrida_efectiva"] == "1"
    and c["vulnerabilidades_correlacionadas"] == "0"
    and c["pares_nuevos_persistidos"] == "0"
}

# Corridas efectivas que vieron cada vulnerabilidad, en orden
vistas = defaultdict(set)
for r in leer("data/raw/afectados_al_ingerir.csv"):
    if r["fila_auditoria"] in efectivas:
        vistas[r["cve_id"]].add(int(r["fila_auditoria"]))
vistas_en_cero = {v for v, filas in vistas.items() if {str(f) for f in filas} & set(cero)}

# 2. Perdidas que pasaron solo por dias en cero
perdidas = defaultdict(set)
for r in leer("data/cleaned/bloque4b_cobertura_vulnerable/nunca_detectadas.csv"):
    perdidas[r["regla"]].add(r["cve_id"])

filas_perdidas = []
solo_cero = {}
for regla, ids in perdidas.items():
    solo = sorted(v for v in ids if vistas[v] and {str(f) for f in vistas[v]} <= set(cero))
    solo_cero[regla] = solo
    for v in solo:
        filas_perdidas.append({
            "regla": regla,
            "cve_id": v,
            "corridas": " ".join(f"{f} ({cero[str(f)]})" for f in sorted(vistas[v])),
        })

# 3. Detecciones demoradas que pasaron por un dia en cero antes de detectarse
demoradas = {"inferencia": 0, "formal": 0}
demoradas_cero = {"inferencia": 0, "formal": 0}
for r in leer("data/cleaned/bloque12b_latencia_deteccion/por_vulnerabilidad.csv"):
    filas = sorted(vistas[r["cve_id"]])
    for via in demoradas:
        previas = r[f"deteccion_{via}_corridas_previas"]
        if previas and int(previas) > 0:
            demoradas[via] += 1
            if {str(f) for f in filas[: int(previas)]} & set(cero):
                demoradas_cero[via] += 1

resumen = [
    ("corridas efectivas en cero", "corridas", len(cero), 40),
    ("dias en cero", "dias", " ".join(sorted(cero.values())), 40),
    ("vulnerabilidades ingeridas en dias en cero", "vulnerabilidades distintas", len(vistas_en_cero), 53),
    ("nunca detectadas, producto afectado", "vulnerabilidades distintas", len(perdidas["vulnerable"]), 58),
    ("nunca detectadas que pasaron solo por dias en cero, producto afectado", "vulnerabilidades distintas", len(solo_cero["vulnerable"]), 63),
    ("nunca detectadas, regla del artefacto", "vulnerabilidades distintas", len(perdidas["artefacto"]), 58),
    ("nunca detectadas que pasaron solo por dias en cero, regla del artefacto", "vulnerabilidades distintas", len(solo_cero["artefacto"]), 63),
    ("detectadas por inferencia despues de una corrida previa", "vulnerabilidades distintas", demoradas["inferencia"], 80),
    ("detectadas por la via formal despues de una corrida previa", "vulnerabilidades distintas", demoradas["formal"], 80),
    ("de esas, formales que pasaron por un dia en cero antes", "vulnerabilidades distintas", demoradas_cero["formal"], 82),
]

with open(SALIDA / "resumen.csv", "w", encoding="utf-8", newline="") as f:
    w = csv.writer(f)
    w.writerow(["medida", "unidad", "valor", "script"])
    for medida, unidad, valor, linea in resumen:
        w.writerow([medida, unidad, valor, f"bloque13_dias_en_cero.py:{linea}"])

with open(SALIDA / "perdidas_en_dias_cero.csv", "w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["regla", "cve_id", "corridas"])
    w.writeheader()
    w.writerows(filas_perdidas)

for medida, unidad, valor, _ in resumen:
    print(f"{medida}: {valor}")
