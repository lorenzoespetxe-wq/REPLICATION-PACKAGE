"""Bloque 28B -- Piso de los rangos afectados que declara Microsoft en los casos de Windows Server.

Lo pidio la tercera revision independiente (21/10): sostenia que el 0 % de error en Windows Server
se debe en parte a que ahi no se pueden detectar errores de version. Este script comprueba, para los
43 casos de Windows Server de la muestra de la via de inferencia, en que compilacion empieza el rango
afectado que declara la CNA. Si empieza en la primera compilacion de la version, ningun equipo de esa
version puede quedar por debajo del rango.

Fuentes:
  - Casos: data/cleaned/bloque6_revision_inferencia/propuesta.csv
  - Registros de la CNA al cierre: data/raw/cvelistv5_cierre/

Salida: data/cleaned/bloque28b_piso_rangos_windows/piso_por_caso.csv y resumen.csv
"""
import csv
import json
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
CASOS = RAIZ / "data" / "cleaned" / "bloque6_revision_inferencia" / "propuesta.csv"
REGISTROS = RAIZ / "data" / "raw" / "cvelistv5_cierre" / "cves" / "2026"
DESTINO = RAIZ / "data" / "cleaned" / "bloque28b_piso_rangos_windows"

PRODUCTOS = {
    "microsoft:windows_server_2016": ("Windows Server 2016", "10.0.14393.0"),
    "microsoft:windows_server_2019": ("Windows Server 2019", "10.0.17763.0"),
    "microsoft:windows_server_2022": ("Windows Server 2022", "10.0.20348.0"),
}

casos = [c for c in csv.DictReader(CASOS.open(encoding="utf-8")) if c["producto_inventario"] in PRODUCTOS]
assert len(casos) == 43, len(casos)

filas = [None] * len(casos)
for i, caso in enumerate(casos):
    nombre, primera = PRODUCTOS[caso["producto_inventario"]]
    registro = json.loads(next(REGISTROS.glob(f"*/{caso['cve_id']}.json")).read_text(encoding="utf-8"))
    pisos = sorted({
        v.get("version")
        for a in registro["containers"]["cna"].get("affected", [])
        if a.get("product", "").startswith(nombre) and "Server Core" not in a.get("product", "")
        for v in a.get("versions", [])
    })
    filas[i] = {
        "id": caso["id"],
        "cve_id": caso["cve_id"],
        "producto_inventario": caso["producto_inventario"],
        "piso_declarado": " ".join(pisos),
        "primera_compilacion": primera,
        "empieza_en_la_primera": pisos == [primera],
    }

resumen = Counter((f["producto_inventario"], f["empieza_en_la_primera"]) for f in filas)

DESTINO.mkdir(parents=True, exist_ok=True)
with (DESTINO / "piso_por_caso.csv").open("w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(filas[0]))
    w.writeheader()
    w.writerows(filas)
with (DESTINO / "resumen.csv").open("w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["producto_inventario", "empieza_en_la_primera", "casos"])
    w.writerows([*k, v] for k, v in sorted(resumen.items()))

print(sorted(resumen.items()))
