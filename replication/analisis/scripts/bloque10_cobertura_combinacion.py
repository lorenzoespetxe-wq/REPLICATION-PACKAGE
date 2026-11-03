"""Bloque 10 -- Cuanto agrega la combinacion de vias respecto de la via formal sola.

Sin base de datos: usa el estado de cada vulnerabilidad al ingerir (historial del orquestador,
bloque 1), la foto de la NVD del 3/10 (bloque 4B), la lista `ids` de las 28 filas de auditoria
y los pares de la via de la CNA (bloque 2).

Mide tres cosas:
  1. Via formal sola "al detectar": vulnerabilidades y pares que la regla del artefacto habria
     correlacionado con el dato que la NVD habia publicado en alguna corrida de la campana.
  2. Correlaciones del artefacto sin coincidencia formal en la foto del cierre.
  3. Pares de la via de la CNA fuera de lo que la NVD vincula al cierre.
Ademas verifica el estado de las 1.018 detectadas en la foto del cierre (retiradas o no).
"""
import csv
import re
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bloque1_cobertura_cierre import activos_que_coinciden, claves_cpe, leer_csv  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
RAW = RAIZ / "data" / "raw"
SALIDA = RAIZ / "data" / "cleaned" / "bloque10_cobertura_combinacion"
FOTO = RAW / "nvd_reconsulta" / "configs_vulnerable_20261003.csv"
PRIMERA_FILA_CAMPANA = 10


def pct(n, d):
    return round(100 * n / d, 1)


def main():
    activos = {int(a["activo_id"]): claves_cpe(a["cpe"]) for a in leer_csv(RAW / "activos_inventario.csv")}
    corridas = leer_csv(RAW / "corridas_campana.csv")
    ultima = max(r["ts_utc"] for r in corridas)
    detectadas = {c for r in corridas for c in re.findall(r"CVE-\d{4}-\d+", r["ids"])}

    # Foto del cierre, regla del artefacto (producto afectado o plataforma), visibles a la ultima corrida.
    foto = leer_csv(FOTO)
    estado_cierre = {c["cve_id"]: c["vuln_status"] for c in foto}
    cierre = {}
    for c in foto:
        if c["published"] <= ultima:
            cierre[c["cve_id"]] = set(activos_que_coinciden(c["cpes_vulnerables"] + " " + c["cpes_plataforma"], activos))
    pares_cierre = {(k, a) for k, v in cierre.items() for a in v}

    # Via formal con el dato publicado al ingerir, en cualquier corrida de la campana.
    al_ingerir = {}
    for r in leer_csv(RAW / "estado_al_ingerir.csv"):
        if int(r["fila_auditoria"]) >= PRIMERA_FILA_CAMPANA and r["cpes"]:
            for a in activos_que_coinciden(r["cpes"], activos):
                al_ingerir.setdefault(r["cve_id"], set()).add(a)
    pares_ingerir = {(k, a) for k, v in al_ingerir.items() for a in v}

    # Pares persistidos de la campana = los formales al cierre que el artefacto persistio (3.780,
    # bloque 8) mas los 68 sin coincidencia formal; aqui solo se usan conteos ya registrados.
    pares_campana, pares_sin_formal = 3848, 68

    filas = [
        {"medida": "correlaciones del artefacto en la campana", "vulnerabilidades": len(detectadas), "pares": pares_campana},
        {"medida": "via formal con el dato publicado al ingerir", "vulnerabilidades": len(set(al_ingerir) & detectadas),
         "pares": len(pares_ingerir)},
        {"medida": "no alcanzadas por la via formal al ingerir", "vulnerabilidades": len(detectadas - set(al_ingerir)),
         "pares": pares_campana - len(pares_ingerir)},
        {"medida": "sin coincidencia formal en la foto del cierre",
         "vulnerabilidades": len(detectadas - {k for k, v in cierre.items() if v}), "pares": pares_sin_formal},
    ]
    for f in filas:
        f["vuln_pct"] = pct(f["vulnerabilidades"], len(detectadas))
        f["pares_pct"] = pct(f["pares"], pares_campana)

    # Via de la CNA contra lo que la NVD vincula al cierre.
    cna = [(r["cve_id"], int(r["activo_id"]), r["persistido_por_el_artefacto"])
           for r in leer_csv(RAIZ / "data" / "cleaned" / "bloque2_vias_cna_cisa" / "pares_via_cna.csv")]
    fuera = {(c, a) for c, a, _ in cna} - pares_cierre
    filas_cna = [
        {"medida": "pares de la via de la CNA", "valor": len(cna)},
        {"medida": "vulnerabilidades de la via de la CNA", "valor": len({c for c, _, _ in cna})},
        {"medida": "pares de la CNA fuera de la coincidencia formal al cierre", "valor": len(fuera)},
        {"medida": "vulnerabilidades de la CNA fuera de la coincidencia formal al cierre", "valor": len({c for c, _ in fuera})},
        {"medida": "  de esos pares, persistidos por el artefacto",
         "valor": sum(1 for c, a, p in cna if (c, a) in fuera and p == "1")},
    ]

    SALIDA.mkdir(parents=True, exist_ok=True)
    for nombre, datos in (("combinacion.csv", filas), ("via_cna_fuera_del_formal.csv", filas_cna)):
        with (SALIDA / nombre).open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(datos[0]))
            w.writeheader()
            w.writerows(datos)

    # Pares de la CNA contra lo que la NVD declara afectado (criterio de la seccion 5.1).
    pares_afectado = {(c["cve_id"], a) for c in foto if c["published"] <= ultima
                      for a in activos_que_coinciden(c["cpes_vulnerables"], activos)}
    fuera_af = {(c, a) for c, a, _ in cna} - pares_afectado
    no_persistidos = {(c, a) for c, a, p in cna if p != "1"}
    for medida, valor in (("pares de la CNA fuera de lo declarado afectado al cierre", len(fuera_af)),
                          ("pares de la CNA no persistidos por el artefacto", len(no_persistidos)),
                          ("  de ellos, declarados afectados por la NVD al cierre", len(no_persistidos & pares_afectado))):
        filas_cna.append({"medida": medida, "valor": valor})
    with (SALIDA / "via_cna_fuera_del_formal.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["medida", "valor"])
        w.writeheader()
        w.writerows(filas_cna)

    # Por activo y en total, con las dos reglas: respaldo al detectar y al cierre (apartados 5.1.2 y
    # 5.1.4). Pares persistidos de la campana leidos de la base (solo lectura). Con la regla de solo
    # producto afectado, un par formal al ingerir cuenta si la foto del cierre declara afectado al activo.
    import bloque8_telemetria as b8
    pares, _, _ = b8.cargar()
    camp = [p for p in pares if p["campana"]]
    por_activo, totales = [], []
    for regla, pares_regla in (("artefacto", pares_cierre), ("vulnerable", pares_afectado)):
        acum, vuln = {}, {"det": set(), "cierre": set()}
        for p in camp:
            par = (p["cve_id"], p["activo_id"])
            cierre_ok = par in pares_regla
            det_ok = par in pares_ingerir and (regla == "artefacto" or cierre_ok)
            r = acum.setdefault(p["hostname"], {"regla": regla, "activo": p["hostname"], "pares": 0,
                                                 "detectar_con": 0, "detectar_sin": 0, "cierre_con": 0, "cierre_sin": 0})
            r["pares"] += 1
            r["detectar_con" if det_ok else "detectar_sin"] += 1
            r["cierre_con" if cierre_ok else "cierre_sin"] += 1
            if det_ok:
                vuln["det"].add(p["cve_id"])
            if cierre_ok:
                vuln["cierre"].add(p["cve_id"])
        por_activo += sorted(acum.values(), key=lambda r: -r["pares"])
        tot = {k: sum(r[k] for r in acum.values()) for k in ("pares", "detectar_con", "detectar_sin", "cierre_con", "cierre_sin")}
        tot.update({"regla": regla, "vuln_detectar_con": len(vuln["det"]), "vuln_cierre_con": len(vuln["cierre"])})
        totales.append(tot)
    for nombre, datos in (("respaldo_por_activo.csv", por_activo), ("respaldo_totales.csv", totales)):
        with (SALIDA / nombre).open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(dict.fromkeys(k for d in datos for k in d)))
            w.writeheader()
            w.writerows(datos)

    # Comprobaciones.
    for t in totales:
        print(t)
    assert totales[0]["detectar_con"] == 656 and totales[0]["cierre_con"] == 3780
    assert totales[1]["detectar_con"] == 574 and totales[1]["cierre_con"] == 3698
    assert pares_ingerir <= pares_cierre, "un par formal al ingerir perdio la coincidencia al cierre"
    assert len(pares_ingerir) == 439 + 217, "formal al ingerir != nacidos formales + promovidos"
    estados = Counter(estado_cierre.get(c, "AUSENTE") for c in detectadas)
    for f in filas + filas_cna:
        print(f)
    print("estado de las detectadas en la foto del cierre:", dict(estados))


if __name__ == "__main__":
    main()
