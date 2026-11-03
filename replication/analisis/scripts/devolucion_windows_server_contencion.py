"""Devolucion del tribunal, observacion 7 -- Coincidencia de nombres en Windows Server (apartados 5.2.2 y 6.3).

La regla de inferencia acepta contencion, no igualdad. Para los casos de la via de inferencia en Windows
Server, este script separa los que el registro nombra con un nombre igual al del inventario de los que
solo coinciden porque el nombre del registro contiene al del inventario, con los nombres que el flujo
leyo en las corridas de la campana.

Entradas: data/cleaned/bloque5_muestra_validacion/universo_inferencia.csv, muestra_inferencia.csv,
          data/raw/afectados_al_ingerir.csv
Salida:   data/cleaned/devolucion_windows_server_contencion/por_caso.csv, resumen.csv, solo_contencion.csv
"""
import csv
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bloque4_reconsulta_inferencia import normalizar  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
MUESTRA = RAIZ / "data" / "cleaned" / "bloque5_muestra_validacion"
INGESTA = RAIZ / "data" / "raw" / "afectados_al_ingerir.csv"
SALIDA = RAIZ / "data" / "cleaned" / "devolucion_windows_server_contencion"
PRIMERA_FILA_CAMPANA = 10


def leer(ruta):
    with ruta.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def main():
    casos = [r for r in leer(MUESTRA / "universo_inferencia.csv") if r["estrato"].startswith("microsoft:windows_server")]
    assert len(casos) == 1688, len(casos)   # control: seccion 5.2.1
    en_muestra = {(r["cve_id"], r["estrato"]) for r in leer(MUESTRA / "muestra_inferencia.csv")}

    nombres = defaultdict(set)
    for r in leer(INGESTA):
        if int(r["fila_auditoria"]) >= PRIMERA_FILA_CAMPANA:
            nombres[r["cve_id"]].update(tuple(x) for x in json.loads(r["afectados"] or "[]"))

    filas = []
    for c in casos:
        vendor, producto = (normalizar(x) for x in c["estrato"].split(":"))
        coinciden = sorted({p for v, p in nombres[c["cve_id"]]
                            if (normalizar(v) in vendor or vendor in normalizar(v))
                            and (normalizar(p) in producto or producto in normalizar(p))})
        iguales = [p for p in coinciden if normalizar(p) == producto]
        filas.append({"cve_id": c["cve_id"], "estrato": c["estrato"], "pares": c["pares"],
                      "en_muestra": int((c["cve_id"], c["estrato"]) in en_muestra),
                      "tipo": "igual" if iguales else ("solo_contencion" if coinciden else "sin_nombres"),
                      "nombres_que_coinciden": json.dumps(coinciden, ensure_ascii=False)})

    solo = [f for f in filas if f["tipo"] == "solo_contencion"]
    resumen = [{"medida": f"casos {t}", "valor": n} for t, n in Counter(f["tipo"] for f in filas).items()]
    resumen += [{"medida": f"casos {t} / {e}", "valor": n}
                for (t, e), n in sorted(Counter((f["tipo"], f["estrato"]) for f in filas).items())]
    resumen.append({"medida": "casos solo_contencion dentro de la muestra", "valor": sum(f["en_muestra"] for f in solo)})
    resumen += [{"medida": f"nombre (cualquier caso): {p}", "valor": n} for p, n in
                Counter(p for f in filas for p in json.loads(f["nombres_que_coinciden"])).most_common()]
    resumen += [{"medida": f"nombre (solo_contencion): {p}", "valor": n} for p, n in
                Counter(p for f in solo for p in json.loads(f["nombres_que_coinciden"])).most_common()]

    SALIDA.mkdir(parents=True, exist_ok=True)
    for nombre, datos in (("por_caso.csv", filas), ("resumen.csv", resumen), ("solo_contencion.csv", solo)):
        if datos:
            with (SALIDA / nombre).open("w", encoding="utf-8", newline="") as f:
                w = csv.DictWriter(f, fieldnames=list(datos[0]))
                w.writeheader()
                w.writerows(datos)
    for r in resumen:
        print(r)


if __name__ == "__main__":
    main()
