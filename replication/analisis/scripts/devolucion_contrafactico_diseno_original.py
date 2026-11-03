"""Devolucion del tribunal, observacion 1 -- Que habria detectado el diseno original durante la campana.

Contrafactico pedido por el tribunal: el diseno original, con los identificadores ya corregidos y su
ventana de tres dias de calendario (la misma de la campana), corrido en las mismas fechas.

Un par (vulnerabilidad, activo) cuenta como detectado cuando se cumplen las dos condiciones:
  1. La NVD ya habia publicado, en alguna corrida en que la vulnerabilidad estaba en la ventana, una
     configuracion que nombra el fabricante y el producto del activo (data/raw/estado_al_ingerir.csv).
  2. La consulta con cpeName del identificador completo devuelve esa vulnerabilidad: es el filtro de
     version que el servidor de la NVD aplicaba (respuestas del 05/10, data/raw/nvd_verificacion_version/,
     verificadas contra los rangos declarados en scripts/bloque9_verificacion_version.py).

Limite: la condicion 2 se lee de la respuesta del 05/10, no de la de cada corrida.

Entradas: data/raw/estado_al_ingerir.csv, data/raw/activos_inventario.csv,
          data/raw/nvd_verificacion_version/*_A_cpeName_p*.json,
          data/raw/nvd_reconsulta/configs_vulnerable_20261003.csv, data/raw/corridas_campana.csv
Salida:   data/cleaned/devolucion_contrafactico_diseno_original/por_producto.csv, resumen.csv
"""
import csv
import json
import statistics
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from bloque1_cobertura_cierre import activos_que_coinciden, claves_cpe, leer_csv  # noqa: E402

RAIZ = Path(__file__).resolve().parent.parent
RAW = RAIZ / "data" / "raw"
RESPUESTAS = RAW / "nvd_verificacion_version"
SALIDA = RAIZ / "data" / "cleaned" / "devolucion_contrafactico_diseno_original"
FECHAS = RAIZ / "data" / "cleaned" / "bloque12b_fecha_configuracion" / "por_vulnerabilidad.csv"
LATENCIA = RAIZ / "data" / "cleaned" / "bloque12b_latencia_deteccion" / "por_vulnerabilidad.csv"
PRIMERA_FILA_CAMPANA = 10
VENTANAS = (3, 7, 20, 30)


def prefijo_archivo(cpe):
    p = cpe.split(":")
    version = p[5] if p[5] != "-" else ""
    return "_".join(x.replace(".", "_") for x in (p[3], p[4], version))


def devueltas_por_cpename(cpe):
    ids = set()
    for ruta in sorted(RESPUESTAS.glob(prefijo_archivo(cpe) + "_A_cpeName_p*.json")):
        ids.update(v["cve"]["id"] for v in json.loads(ruta.read_text(encoding="utf-8")).get("vulnerabilities", []))
    return ids


def main():
    inv = leer_csv(RAW / "activos_inventario.csv")
    claves = {int(a["activo_id"]): claves_cpe(a["cpe"]) for a in inv}
    cpe_de = {int(a["activo_id"]): a["cpe"] for a in inv}
    devueltas = {cpe: devueltas_por_cpename(cpe) for cpe in set(cpe_de.values())}

    con_configuracion = set()   # pares cuya configuracion estaba publicada dentro de la ventana
    estado = leer_csv(RAW / "estado_al_ingerir.csv")
    for r in estado:
        if int(r["fila_auditoria"]) >= PRIMERA_FILA_CAMPANA and r["cpes"]:
            con_configuracion.update((r["cve_id"], aid) for aid in activos_que_coinciden(r["cpes"], claves))
    detectados = {(c, a) for c, a in con_configuracion if c in devueltas[cpe_de[a]]}

    # que habria devuelto cada corrida: activos con al menos un resultado
    filas_corrida = sorted({int(r["fila_auditoria"]) for r in estado if int(r["fila_auditoria"]) >= PRIMERA_FILA_CAMPANA})
    activos_con_resultado = {f: set() for f in filas_corrida}
    for r in estado:
        f = int(r["fila_auditoria"])
        if f >= PRIMERA_FILA_CAMPANA and r["cpes"]:
            activos_con_resultado[f].update(a for a in activos_que_coinciden(r["cpes"], claves)
                                             if r["cve_id"] in devueltas[cpe_de[a]])

    ultima = max(r["ts_utc"] for r in leer_csv(RAW / "corridas_campana.csv"))
    foto = [c for c in leer_csv(RAW / "nvd_reconsulta" / "configs_vulnerable_20261003.csv") if c["published"] <= ultima]
    afectados = {(c["cve_id"], a) for c in foto for a in activos_que_coinciden(c["cpes_vulnerables"], claves)}
    assert len(afectados) == 5810, len(afectados)   # control: cifra de la seccion 5.1.3

    # sensibilidad a la ventana: un par entra si la configuracion llego dentro de los dias de ventana
    dias_hasta = {r["cve_id"]: float(r["dias_publicacion_a_configuracion"]) for r in leer_csv(FECHAS)}
    for r in leer_csv(LATENCIA):
        if r["momento_del_dato"] == "primera_corrida":
            dias_hasta[r["cve_id"]] = float(r["deteccion_formal_horas"]) / 24
    posibles = {(c, a) for c, a in afectados if c in devueltas[cpe_de[a]] and c in dias_hasta}
    sensibilidad = []
    for ventana in VENTANAS:
        pares = {(c, a) for c, a in posibles if dias_hasta[c] <= ventana}
        demoras = [dias_hasta[c] for c in {c for c, _ in pares}]
        sensibilidad.append({"medida": f"ventana de {ventana} dias: pares", "valor": len(pares)})
        sensibilidad.append({"medida": f"ventana de {ventana} dias: vulnerabilidades", "valor": len(demoras)})
        sensibilidad.append({"medida": f"ventana de {ventana} dias: mediana de dias hasta detectar",
                             "valor": round(statistics.median(demoras), 1)})

    por_producto = defaultdict(lambda: {"activos": set(), "en_ventana": 0, "detectados": 0, "afectados_cierre": 0})
    for a, cpe in cpe_de.items():
        por_producto[cpe]["activos"].add(a)
    for c, a in con_configuracion:
        por_producto[cpe_de[a]]["en_ventana"] += 1
    for c, a in detectados:
        por_producto[cpe_de[a]]["detectados"] += 1
    for c, a in afectados:
        por_producto[cpe_de[a]]["afectados_cierre"] += 1

    filas = [{"cpe": k, "activos": len(v["activos"]), "pares_con_configuracion_en_ventana": v["en_ventana"],
              "pares_que_devuelve_con_filtro_de_version": v["detectados"], "pares_afectados_al_cierre": v["afectados_cierre"]}
             for k, v in sorted(por_producto.items(), key=lambda x: -x[1]["detectados"])]
    resumen = [
        {"medida": "pares con configuracion publicada dentro de la ventana", "valor": len(con_configuracion)},
        {"medida": "vulnerabilidades con configuracion publicada dentro de la ventana",
         "valor": len({c for c, _ in con_configuracion})},
        {"medida": "pares que el diseno original habria detectado", "valor": len(detectados)},
        {"medida": "vulnerabilidades que el diseno original habria detectado", "valor": len({c for c, _ in detectados})},
        {"medida": "pares afectados al cierre", "valor": len(afectados)},
        {"medida": "vulnerabilidades afectadas al cierre", "valor": len({c for c, _ in afectados})},
        {"medida": "pares detectados que ademas estan afectados al cierre", "valor": len(detectados & afectados)},
        {"medida": "vulnerabilidades afectadas al cierre con algun par detectado",
         "valor": len({c for c, _ in detectados & afectados})},
        {"medida": "corridas de la campana", "valor": len(filas_corrida)},
        {"medida": "corridas sin resultados para ningun activo",
         "valor": sum(not v for v in activos_con_resultado.values())},
        {"medida": "activos con resultado por corrida (maximo)", "valor": max(len(v) for v in activos_con_resultado.values())},
        {"medida": "activos con resultado por corrida (mediana)",
         "valor": statistics.median(len(v) for v in activos_con_resultado.values())},
    ] + sensibilidad
    SALIDA.mkdir(parents=True, exist_ok=True)
    for nombre, datos in (("por_producto.csv", filas), ("resumen.csv", resumen)):
        with (SALIDA / nombre).open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(datos[0]))
            w.writeheader()
            w.writerows(datos)
    for r in filas + resumen:
        print(r)


if __name__ == "__main__":
    main()
