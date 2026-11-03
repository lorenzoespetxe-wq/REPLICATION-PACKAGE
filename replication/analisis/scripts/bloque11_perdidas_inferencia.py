"""Bloque 11 -- Lo que la via de inferencia no encontro (seccion 5.2.4).

Mide los falsos negativos de la inferencia por si sola, sin la via formal: de los pares que la
NVD declara afectados en la foto de cierre (03/10, solo producto afectado, criterio de la
seccion 5.1), cuantos habria encontrado la regla de inferencia del artefacto con los nombres
de fabricante y producto que el flujo leyo al ingerir, en cualquier corrida de la campana.

Para cada par que no habria encontrado, el motivo:
  - sin_nombres_del_fabricante / nombres_bajo_el_umbral / fabricante_no_coincide /
    producto_no_coincide: el motivo de la regla, con los nombres al ingerir (copia de la regla
    en scripts/bloque4_reconsulta_inferencia.py, ya controlada contra la base en el bloque 4).
Y si con los nombres del 02/10 (afectados_20261002.csv) la regla lo habria encontrado, para
separar lo que falta en el registro de lo que falla en la comparacion.

Entradas: data/raw/nvd_reconsulta/configs_vulnerable_20261003.csv, afectados_20261002.csv,
          data/raw/afectados_al_ingerir.csv, data/raw/corridas_campana.csv,
          data/raw/activos_inventario.csv
Salida:   data/cleaned/bloque11_precision_inferencia/perdidas_inferencia.csv (por par) y
          perdidas_resumen.csv (sin titulos ni notas)
"""
import csv
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bloque1_cobertura_cierre import activos_que_coinciden, claves_cpe, leer_csv  # noqa: E402
from bloque4_reconsulta_inferencia import inferencia, normalizar  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
RAW = RAIZ / "data" / "raw"
FOTO = RAW / "nvd_reconsulta" / "configs_vulnerable_20261003.csv"
NOMBRES_0210 = RAW / "nvd_reconsulta" / "afectados_20261002.csv"
SALIDA = RAIZ / "data" / "cleaned" / "bloque11_precision_inferencia"
PRIMERA_FILA_CAMPANA = 10


def main():
    inv = leer_csv(RAW / "activos_inventario.csv")
    claves = {int(a["activo_id"]): claves_cpe(a["cpe"]) for a in inv}
    activo = {}
    for a in inv:
        p = a["cpe"].split(":")
        activo[int(a["activo_id"])] = {"hostname": a["hostname"], "cpe": a["cpe"],
                                       "vendor": normalizar(p[3]), "product": normalizar(p[4])}
    ultima = max(r["ts_utc"] for r in leer_csv(RAW / "corridas_campana.csv"))

    # nombres que el flujo leyo al ingerir, unidos sobre las corridas de la campana
    al_ingerir = {}
    for r in leer_csv(RAW / "afectados_al_ingerir.csv"):
        if int(r["fila_auditoria"]) >= PRIMERA_FILA_CAMPANA:
            al_ingerir.setdefault(r["cve_id"], set()).update(tuple(x) for x in json.loads(r["afectados"] or "[]"))
    nombres_0210 = {r["cve_id"]: [tuple(x) for x in json.loads(r["afectados"] or "[]")]
                    for r in leer_csv(NOMBRES_0210)}

    afectados = [(c["cve_id"], aid) for c in leer_csv(FOTO) if c["published"] <= ultima
                 for aid in activos_que_coinciden(c["cpes_vulnerables"], claves)]
    assert len(afectados) == 5810, len(afectados)   # control: cifra de la seccion 5.1.3

    filas = []
    for cve, aid in afectados:
        ingeridos = sorted(al_ingerir.get(cve, set()))
        ok, motivo = inferencia(activo[aid], ingeridos) if cve in al_ingerir else (False, "no_ingerida_en_campana")
        if ok:
            continue
        ok_0210, _ = inferencia(activo[aid], nombres_0210.get(cve, []))
        filas.append({"cve_id": cve, "hostname": activo[aid]["hostname"], "cpe_inventario": activo[aid]["cpe"],
                      "motivo_al_ingerir": motivo, "encontrado_con_nombres_0210": int(ok_0210),
                      "nombres_al_ingerir": json.dumps(ingeridos, ensure_ascii=False)})
    SALIDA.mkdir(parents=True, exist_ok=True)
    campos = ["cve_id", "hostname", "cpe_inventario", "motivo_al_ingerir", "encontrado_con_nombres_0210",
              "nombres_al_ingerir"]
    with (SALIDA / "perdidas_inferencia.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(filas)

    resumen = [{"medida": "pares declarados afectados al cierre", "valor": len(afectados)},
               {"medida": "vulnerabilidades declaradas afectadas al cierre",
                "valor": len({c for c, _ in afectados})},
               {"medida": "pares que la inferencia no habria encontrado", "valor": len(filas)},
               {"medida": "vulnerabilidades con algun par no encontrado", "valor": len({f["cve_id"] for f in filas})},
               {"medida": "vulnerabilidades sin ningun par encontrado",
                "valor": sum(1 for c, n in Counter(f["cve_id"] for f in filas).items()
                             if n == sum(1 for c2, _ in afectados if c2 == c))}]
    for (prod, mot), n in sorted(Counter((f["cpe_inventario"].split(":")[4], f["motivo_al_ingerir"])
                                         for f in filas).items(), key=lambda x: -x[1]):
        resumen.append({"medida": f"pares no encontrados: {prod} / {mot}", "valor": n})
    resumen.append({"medida": "pares no encontrados que con los nombres del 02/10 si se encontrarian",
                    "valor": sum(f["encontrado_con_nombres_0210"] for f in filas)})
    with (SALIDA / "perdidas_resumen.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["medida", "valor"])
        w.writeheader()
        w.writerows(resumen)
    for r in resumen:
        print(r["medida"], r["valor"])


if __name__ == "__main__":
    main()
