"""Devolucion del tribunal, observacion 5 -- Demora de la NVD con observaciones censuradas (apartado 5.4.3).

Estimador de Kaplan-Meier del tiempo entre la publicacion y la primera configuracion de la NVD, sobre
las 1.018 vulnerabilidades correlacionadas. Una sola fecha de cierre: la consulta a la NVD del 03/10.
  - Evento: las 922 con fecha en el historial de la NVD (bloque 12B) y las 47 que ya tenian
    configuracion en la primera corrida, fechadas en esa corrida (cota superior).
  - Censura: las 49 sin configuracion el 03/10, al tiempo transcurrido hasta esa consulta.

Reporta tambien la alternativa minima: cada horizonte restringido a las vulnerabilidades que llevaban
al menos ese seguimiento al cierre; y el reparto por semana de publicacion.

Entradas: data/cleaned/bloque12b_latencia_deteccion/por_vulnerabilidad.csv,
          data/cleaned/bloque12b_fecha_configuracion/por_vulnerabilidad.csv,
          data/raw/nvd_reconsulta/configs_vulnerable_20261003.csv y su meta
Salida:   data/cleaned/devolucion_supervivencia_nvd/resumen.csv, por_semana.csv, censuradas.csv
"""
import csv
import json
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
LIMPIO = RAIZ / "data" / "cleaned"
FOTO = RAIZ / "data" / "raw" / "nvd_reconsulta"
SALIDA = LIMPIO / "devolucion_supervivencia_nvd"
HORIZONTES = (3, 5, 7, 10, 14, 21)
PERCENTILES = (25, 50, 75, 90)


def leer(ruta):
    with ruta.open(encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def kaplan_meier(tiempos):
    """tiempos: lista de (dias, hubo_evento). Devuelve [(dia, proporcion con configuracion)]."""
    eventos, salidas = Counter(), Counter()
    for t, ev in tiempos:
        salidas[t] += 1
        if ev:
            eventos[t] += 1
    en_riesgo, supervivencia, curva = len(tiempos), 1.0, []
    for t in sorted(salidas):
        if eventos[t]:
            supervivencia *= 1 - eventos[t] / en_riesgo
            curva.append((t, 1 - supervivencia))
        en_riesgo -= salidas[t]
    return curva


def valor_en(curva, dia):
    p = 0.0
    for t, q in curva:
        if t > dia:
            break
        p = q
    return p


def percentil(curva, pct):
    return next((t for t, q in curva if q >= pct / 100), None)


def main():
    consulta = datetime.fromisoformat(
        json.loads((FOTO / "meta_configs_vulnerable_20261003.json").read_text(encoding="utf-8"))["consulta_utc"]
    ).replace(tzinfo=None)
    fechas = {r["cve_id"]: r for r in leer(LIMPIO / "bloque12b_fecha_configuracion" / "por_vulnerabilidad.csv")}
    estado = {r["cve_id"]: r for r in leer(FOTO / "configs_vulnerable_20261003.csv")}
    filas = leer(LIMPIO / "bloque12b_latencia_deteccion" / "por_vulnerabilidad.csv")
    assert len(filas) == 1018, len(filas)

    tiempos, censuradas, por_semana = [], [], defaultdict(Counter)
    for r in filas:
        cve = r["cve_id"]
        pub = datetime.fromisoformat(r["publicacion_utc"])
        seguimiento = (consulta - pub).total_seconds() / 86400
        semana = pub.strftime("%G-S%V")
        por_semana[semana]["total"] += 1
        if cve in fechas:
            t, ev = float(fechas[cve]["dias_publicacion_a_configuracion"]), True
        elif r["momento_del_dato"] == "primera_corrida":
            t, ev = float(r["deteccion_formal_horas"]) / 24, True
        else:
            t, ev = seguimiento, False
            censuradas.append({"cve_id": cve, "publicacion_utc": r["publicacion_utc"], "dias_al_cierre": round(t, 2),
                               "vuln_status": estado[cve]["vuln_status"]})
            por_semana[semana]["sin_configuracion"] += 1
        por_semana[semana]["seguimiento_min"] = min(por_semana[semana].get("seguimiento_min", 999), int(seguimiento))
        tiempos.append((t, ev, seguimiento))
    curva = kaplan_meier([(t, ev) for t, ev, _ in tiempos])

    resumen = [{"medida": "vulnerabilidades", "valor": len(tiempos)},
               {"medida": "con configuracion (evento)", "valor": sum(ev for _, ev, _ in tiempos)},
               {"medida": "censuradas al 03/10", "valor": len(censuradas)},
               {"medida": "seguimiento minimo (dias)", "valor": round(min(s for *_, s in tiempos), 2)},
               {"medida": "seguimiento maximo (dias)", "valor": round(max(s for *_, s in tiempos), 2)}]
    for p in PERCENTILES:
        v = percentil(curva, p)
        resumen.append({"medida": f"percentil {p} Kaplan-Meier (dias)", "valor": None if v is None else round(v, 2)})
    for h in HORIZONTES:
        completas = [(t, ev) for t, ev, s in tiempos if s >= h]
        con_dato = sum(ev and t <= h for t, ev in completas)
        ingenuo = sum(ev and t <= h for t, ev, _ in tiempos)
        resumen += [{"medida": f"a {h} dias: sobre las 1.018, sin tratar censura (%)", "valor": round(100 * ingenuo / len(tiempos), 1)},
                    {"medida": f"a {h} dias: Kaplan-Meier (%)", "valor": round(100 * valor_en(curva, h), 1)},
                    {"medida": f"a {h} dias: solo con seguimiento completo (n)", "valor": len(completas)},
                    {"medida": f"a {h} dias: solo con seguimiento completo (%)", "valor": round(100 * con_dato / len(completas), 1)}]
    semanas = [{"semana": k, "vulnerabilidades": v["total"], "sin_configuracion": v["sin_configuracion"],
                "seguimiento_minimo_dias": v["seguimiento_min"]} for k, v in sorted(por_semana.items())]
    SALIDA.mkdir(parents=True, exist_ok=True)
    for nombre, datos in (("resumen.csv", resumen), ("por_semana.csv", semanas), ("censuradas.csv", censuradas)):
        with (SALIDA / nombre).open("w", encoding="utf-8", newline="") as f:
            w = csv.DictWriter(f, fieldnames=list(datos[0]))
            w.writeheader()
            w.writerows(datos)
    for r in resumen + semanas:
        print(r)
    print(Counter(c["vuln_status"] for c in censuradas))


if __name__ == "__main__":
    main()
