"""Bloque 7 -- Prerevision del censo de la via formal (60 vulnerabilidades, F01 a F60).

Para cada vulnerabilidad y cada producto del inventario con que correlaciono, lee el registro CVE
tal como lo publico la CNA (corpus local cvelistV5 de cierre) y propone un veredicto:
  - el producto figura como afectado en el registro -> correcto; la version no es verificable
    porque el inventario no registra el numero de actualizacion de los Windows (criterio del
    bloque 6: afectado salvo que este parcheado);
  - el producto no figura -> error. Si el registro afecta a otro producto que corre sobre el del
    inventario (Chrome sobre macOS), el tipo es plataforma.

Entradas: data/cleaned/bloque5_muestra_validacion/planilla_revision.csv,
          data/raw/cvelistv5_cierre/cves/, data/raw/activos_inventario.csv
Salida:   data/cleaned/bloque7_revision_formal/propuesta.csv (una fila por vulnerabilidad y producto)
"""
import csv
import json
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CORPUS = RAIZ / "data" / "raw" / "cvelistv5_cierre" / "cves"
PLANILLA = RAIZ / "data" / "cleaned" / "bloque5_muestra_validacion" / "planilla_revision.csv"
INVENTARIO = RAIZ / "data" / "raw" / "activos_inventario.csv"
SALIDA = RAIZ / "data" / "cleaned" / "bloque7_revision_formal"

NOMBRE_EN_AVISO = {"windows_10_22h2": "Windows 10 Version 22H2", "windows_server_2016": "Windows Server 2016",
                   "windows_server_2019": "Windows Server 2019", "windows_server_2022": "Windows Server 2022",
                   "macos": "macOS"}


def registro(cve):
    _, anio, num = cve.split("-")
    return json.loads((CORPUS / anio / (num[:-3] + "xxx") / f"{cve}.json").read_text(encoding="utf-8"))


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)
    inv = list(csv.DictReader(INVENTARIO.open(encoding="utf-8")))
    producto_de = {a["hostname"]: a["cpe"].split(":")[4] for a in inv}
    version_de = {a["hostname"]: a["cpe"].split(":")[5] for a in inv}
    filas = []
    for r in csv.DictReader(PLANILLA.open(encoding="utf-8")):
        if r["via"] != "formal":
            continue
        cve = r["cve_id"]
        j = registro(cve)
        cna = j["cveMetadata"].get("assignerShortName", "")
        afectados = [a.get("product", "") for a in j["containers"]["cna"].get("affected", [])]
        hosts_por_producto = {}
        for h in r["activos"].split():
            hosts_por_producto.setdefault(producto_de[h], []).append(h)
        for prod, hosts in sorted(hosts_por_producto.items()):
            nombre = NOMBRE_EN_AVISO[prod]
            if nombre in afectados:
                pa, ok, tipo = "si", "si", ""
                vr = "no verificable" if version_de[hosts[0]] == "-" else "si"
                motivo = f"{nombre} figura como afectado en el registro"
            else:
                pa, ok, vr = "solo plataforma", "no", ""
                tipo = "plataforma"
                motivo = (f"el registro afecta solo a {', '.join(afectados)}, que el inventario no registra; "
                          f"{nombre} es la plataforma sobre la que corre")
            filas.append({"id": r["id"], "cve_id": cve, "cna": cna, "producto_inventario": prod,
                          "activos": " ".join(hosts), "pares": len(hosts),
                          "aviso_url": (f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
                                        if cna == "microsoft" else
                                        (j["containers"]["cna"].get("references") or [{"url": ""}])[0]["url"]),
                          "producto_afectado_segun_aviso": pa, "version_en_rango": vr,
                          "par_correcto_propuesto": ok, "tipo_error_propuesto": tipo, "motivo": motivo})
    with (SALIDA / "propuesta.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0].keys()))
        w.writeheader()
        w.writerows(filas)
    porvuln = Counter(all(f["par_correcto_propuesto"] == "si" for f in filas if f["id"] == i)
                      for i in sorted({f["id"] for f in filas}))
    print("vulnerabilidades correctas/con error:", porvuln)
    print("pares:", Counter((f["par_correcto_propuesto"], f["tipo_error_propuesto"]) for f in filas
                            for _ in range(f["pares"])))


if __name__ == "__main__":
    main()
