"""Bloque 5 -- Cruce de los pares de la via de la CNA no persistidos contra la foto de cierre de la NVD.

Los 2.121 pares que la via de la CNA habria correlacionado y el artefacto no persistio (bloque 2)
se agrupan por activo; para las vulnerabilidades de las cuatro estaciones Windows 10 se verifica si
la NVD, en la reconsulta de cierre, declara `windows_10_22h2` como producto afectado
(`vulnerable=true`), solo como plataforma, o si la vulnerabilidad sigue sin analizar.
Reemplaza al tercer grupo de la muestra de validacion (decision 17 del cronograma).

Entradas: data/cleaned/bloque2_vias_cna_cisa/pares_via_cna.csv,
          data/raw/nvd_reconsulta/configs_vulnerable_*.csv (ultima)
Salida:   data/cleaned/bloque5_cruce_cna_nvd/cruce.csv, resumen.csv (sin titulos ni notas)
"""
import csv
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
PARES = RAIZ / "data" / "cleaned" / "bloque2_vias_cna_cisa" / "pares_via_cna.csv"
FOTO = sorted((RAIZ / "data" / "raw" / "nvd_reconsulta").glob("configs_vulnerable_*.csv"))[-1]
SALIDA = RAIZ / "data" / "cleaned" / "bloque5_cruce_cna_nvd"
ESTACIONES = {"ws-hr-01", "ws-hr-02", "ws-finance-01", "ws-finance-02"}
PRODUCTO = "windows_10_22h2"


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)
    pares = [r for r in csv.DictReader(PARES.open(encoding="utf-8")) if r["persistido_por_el_artefacto"] == "0"]
    nvd = {r["cve_id"]: r for r in csv.DictReader(FOTO.open(encoding="utf-8"))}
    cves = sorted({r["cve_id"] for r in pares if r["hostname"] in ESTACIONES})
    filas = []
    for c in cves:
        r = nvd.get(c)
        if r is None:
            clase = "fuera de la foto"
        elif PRODUCTO in r["cpes_vulnerables"].lower():
            clase = "producto afectado"
        elif PRODUCTO in r["cpes_plataforma"].lower():
            clase = "solo plataforma"
        elif r["n_configs"] == "0":
            clase = f"sin analizar ({r['vuln_status']})"
        else:
            clase = "analizada, sin windows_10_22h2"
        filas.append({"cve_id": c, "clase_nvd": clase})
    with (SALIDA / "cruce.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["cve_id", "clase_nvd"])
        w.writeheader()
        w.writerows(filas)
    resumen = [{"medida": "pares no persistidos", "valor": len(pares)},
               {"medida": "pares en las cuatro estaciones Windows 10",
                "valor": sum(r["hostname"] in ESTACIONES for r in pares)},
               {"medida": "vulnerabilidades en esas estaciones", "valor": len(cves)},
               *({"medida": f"vulnerabilidades: {k}", "valor": v}
                 for k, v in sorted(Counter(f["clase_nvd"] for f in filas).items())),
               {"medida": "foto de la NVD", "valor": FOTO.name}]
    with (SALIDA / "resumen.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["medida", "valor"])
        w.writeheader()
        w.writerows(resumen)
    for r in resumen:
        print(r["medida"], r["valor"])


if __name__ == "__main__":
    main()
