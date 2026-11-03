"""Bloque 12B -- Fecha en que la NVD agrego la configuracion, segun su historial (seccion 5.4).

scripts/bloque12b_latencia_deteccion.py solo acota el momento en que la NVD publico la
configuracion de cada vulnerabilidad: entre la ultima corrida que la vio sin dato y la primera
que la vio con dato (dentro de la ventana) o la ultima modificacion que declaraba la NVD el 3/10
(despues de la ventana). Este script toma la fecha exacta del historial de cambios de la NVD
(descargado por scripts/bloque12b_descarga_historial_nvd.py): el primer evento cuyo detalle
tiene type = "CPE Configuration" y action = "Added". En la NVD ese detalle llega normalmente en
el evento "Initial Analysis" que firma nvd@nist.gov.

Ademas verifica que la fecha caiga entre las cotas del bloque 12B, recalculadas con las marcas
de tiempo exactas (no las redondeadas a centesimos de dia del CSV):
  piso  = ultima corrida que vio la vulnerabilidad sin configuracion (data/raw/estado_al_ingerir.csv);
  techo = primera corrida que la vio con configuracion (dentro de la ventana) o la ultima
          modificacion declarada por la NVD el 3/10 (despues de la ventana).
Dentro de cotas: piso < fecha <= techo.

Percentiles: statistics.quantiles(..., n=100, method="inclusive") (interpolacion lineal).

Unidad: vulnerabilidades distintas. Universo: las 922 con momento_del_dato = dentro_de_la_ventana
o despues_de_la_ventana en data/cleaned/bloque12b_latencia_deteccion/por_vulnerabilidad.csv.
Entradas: ese CSV; data/raw/nvd_historial/<CVE>.json; data/raw/estado_al_ingerir.csv;
data/raw/nvd_reconsulta/configs_vulnerable_20261003.csv.
Salidas (data/cleaned/bloque12b_fecha_configuracion/): por_vulnerabilidad.csv, resumen.csv
"""
import csv
import json
import statistics
from datetime import datetime
from inspect import currentframe
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
RAW = RAIZ / "data" / "raw"
HISTORIAL = RAW / "nvd_historial"
ENTRADA = RAIZ / "data" / "cleaned" / "bloque12b_latencia_deteccion" / "por_vulnerabilidad.csv"
SALIDA = RAIZ / "data" / "cleaned" / "bloque12b_fecha_configuracion"
GRUPOS = ("dentro_de_la_ventana", "despues_de_la_ventana")
TIPO = "CPE Configuration"
SCRIPT = Path(__file__).name

RESUMEN = []


def reg(medida, unidad, valor):
    RESUMEN.append({"medida": medida, "unidad": unidad, "valor": valor,
                    "script": f"{SCRIPT}:{currentframe().f_back.f_lineno}"})


def fecha(texto):
    return datetime.fromisoformat(texto.replace(" ", "T")[:19])


def dias(desde, hasta):
    return (fecha(hasta) - fecha(desde)).total_seconds() / 86400


def distribucion(xs):
    q = statistics.quantiles(xs, n=100, method="inclusive")
    return {"min": min(xs), "p25": q[24], "mediana": statistics.median(xs), "p75": q[74], "p90": q[89],
            "max": max(xs)}


def eventos_cpe(cve):
    """Eventos del historial con detalle CPE Configuration, en orden cronologico."""
    datos = json.loads((HISTORIAL / f"{cve}.json").read_text(encoding="utf-8"))
    eventos = []
    for c in sorted(datos["cveChanges"], key=lambda c: c["change"]["created"]):
        ch = c["change"]
        acciones = {d.get("action") for d in ch.get("details", []) if d.get("type") == TIPO}
        if acciones:
            eventos.append((ch["created"], ch["eventName"], ch.get("sourceIdentifier", ""), acciones))
    return eventos


def main():
    with ENTRADA.open(encoding="utf-8") as f:
        base = [r for r in csv.DictReader(f) if r["momento_del_dato"] in GRUPOS]
    cves = {r["cve_id"] for r in base}
    vistas = {}
    with (RAW / "estado_al_ingerir.csv").open(encoding="utf-8") as f:
        for r in csv.DictReader(f):
            if r["cve_id"] in cves:
                vistas.setdefault(r["cve_id"], []).append((r["ts_utc"], int(r["n_configs"])))
    with (RAW / "nvd_reconsulta" / "configs_vulnerable_20261003.csv").open(encoding="utf-8") as f:
        ultima_mod = {r["cve_id"]: r["last_modified"] for r in csv.DictReader(f) if r["cve_id"] in cves}

    filas = []
    for r in sorted(base, key=lambda r: r["cve_id"]):
        cve, pub, grupo = r["cve_id"], r["publicacion_utc"], r["momento_del_dato"]
        vs = sorted(vistas[cve])
        if grupo == "dentro_de_la_ventana":
            techo = next(t for t, n in vs if n > 0)
            piso = [t for t, n in vs if n == 0 and t < techo][-1]
        else:
            piso, techo = [t for t, n in vs if n == 0][-1], ultima_mod[cve]
        fila = {"cve_id": cve, "grupo": grupo, "publicacion_utc": pub, "fecha_configuracion_utc": "",
                "dias_publicacion_a_configuracion": "", "evento": "", "fuente_evento": "",
                "cota_inferior_utc": piso[:19], "cota_superior_utc": techo[:19], "within_bounds": "", "notas": ""}
        notas = []
        if not (HISTORIAL / f"{cve}.json").exists():
            fila["notas"] = "historial no descargado"
            filas.append(fila)
            continue
        eventos = eventos_cpe(cve)
        altas = [e for e in eventos if "Added" in e[3]]
        if not altas:
            acciones = sorted({a for e in eventos for a in e[3]})
            notas.append("sin evento CPE Configuration Added" + (f" (acciones: {acciones})" if eventos else ""))
        else:
            creado, nombre, fuente, _ = altas[0]
            fila.update({"fecha_configuracion_utc": creado[:19], "evento": nombre, "fuente_evento": fuente,
                         "dias_publicacion_a_configuracion": round(dias(pub, creado), 2),
                         "within_bounds": fecha(piso) < fecha(creado) <= fecha(techo)})
            if nombre != "Initial Analysis":
                notas.append(f"alta en evento distinto de Initial Analysis ({nombre})")
            if fuente != "nvd@nist.gov":
                notas.append(f"alta firmada por {fuente}")
            if fecha(creado) <= fecha(piso):
                notas.append("fecha anterior o igual a la ultima corrida sin dato")
            elif fecha(creado) > fecha(techo):
                notas.append("fecha posterior a la cota superior")
            quitadas = [e for e in eventos if e[0] > creado and "Removed" in e[3]]
            if quitadas:
                notas.append("configuracion eliminada despues: "
                             + "; ".join(f"{e[0][:19]} {e[1]} {sorted(e[3])}" for e in quitadas))
            if len(altas) > 1:
                notas.append(f"{len(altas)} eventos con alta de configuracion")
        fila["notas"] = " | ".join(notas)
        filas.append(fila)

    con = [f for f in filas if f["fecha_configuracion_utc"]]
    reg("vulnerabilidades consultadas al historial de la NVD", "vulnerabilidades", len(filas))
    reg("con fecha de alta de la configuracion", "vulnerabilidades", len(con))
    reg("sin fecha de alta de la configuracion", "vulnerabilidades", len(filas) - len(con))
    reg("fecha dentro de las cotas del bloque 12B", "vulnerabilidades", sum(f["within_bounds"] is True for f in con))
    reg("fecha fuera de las cotas del bloque 12B", "vulnerabilidades", sum(f["within_bounds"] is False for f in con))
    reg("alta de la configuracion en el evento Initial Analysis", "vulnerabilidades",
        sum(f["evento"] == "Initial Analysis" for f in con))
    reg("con alguna anomalia anotada", "vulnerabilidades", sum(bool(f["notas"]) for f in filas))
    for nombre, g in (("total", con),) + tuple((m, [f for f in con if f["grupo"] == m]) for m in GRUPOS):
        reg(f"{nombre}: vulnerabilidades con fecha", "vulnerabilidades", len(g))
        if len(g) > 1:
            for k, v in distribucion([f["dias_publicacion_a_configuracion"] for f in g]).items():
                reg(f"{nombre}: dias de la publicacion al alta de la configuracion ({k})", "dias", round(v, 2))
        reg(f"{nombre}: fuera de las cotas del bloque 12B", "vulnerabilidades",
            sum(f["within_bounds"] is False for f in g))

    # Acumulado sobre las 1.018 correlacionadas: cuantas tenian configuracion a los N dias de publicadas.
    # Las de la primera corrida ya la tenian (<= 1,2 dias); las sin dato al 3/10 no suman en ningun plazo.
    with ENTRADA.open(encoding="utf-8") as f:
        todas = list(csv.DictReader(f))
    primera = sum(t["momento_del_dato"] == "primera_corrida" for t in todas)
    for plazo in (3, 5, 7, 10, 14, 21):
        n = primera + sum(f["dias_publicacion_a_configuracion"] <= plazo for f in con)
        reg(f"correlacionadas con configuracion a los {plazo} dias de publicadas", "vulnerabilidades", n)
        reg(f"correlacionadas con configuracion a los {plazo} dias de publicadas (%)", "% de 1.018",
            round(100 * n / len(todas), 1))

    SALIDA.mkdir(parents=True, exist_ok=True)
    with (SALIDA / "por_vulnerabilidad.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0]))
        w.writeheader()
        w.writerows(filas)
    with (SALIDA / "resumen.csv").open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["medida", "unidad", "valor", "script"])
        w.writeheader()
        w.writerows(RESUMEN)
    for r in RESUMEN:
        print(f"{r['medida']}: {r['valor']}")


if __name__ == "__main__":
    main()
