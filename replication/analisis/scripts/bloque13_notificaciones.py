"""Bloque 13 -- Envio y volumen de las notificaciones de la campana (seccion 5.6).

Verifica contra la base:
  - que todo par notificado tiene el identificador de mensaje que el nodo "Update Alert State"
    escribe con la respuesta del nodo de Gmail (solo se ejecuta despues de un envio aceptado);
  - que ningun par con indice >= 0,40 quedo sin notificar;
  - en que corridas salieron los correos (fecha de ingesta, hora local UTC-3);
  - el margen del umbral: indice maximo de los no notificados y minimo de los notificados;
  - el par no notificado mas cercano al umbral en el escenario de exposicion duplicada (3.6).

Entradas: base (solo lectura)
Salidas:  data/cleaned/bloque13_notificaciones/resumen.csv
          data/cleaned/bloque13_notificaciones/por_corrida.csv
          (sin titulos ni notas)
"""
import csv
import io
import subprocess
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "data/cleaned/bloque13_notificaciones"
CONTENEDOR = "postgres_db"
UMBRAL = 0.40
ESCENARIO = {"cvss": 0.125, "epss": 0.225, "kev": 0.275, "crit": 0.175, "exp": 0.20}  # seccion 3.6

SQL_PARES = """
SELECT t.cve_id, a.hostname, t.estado, t.irc_score, t.cvss_score, t.epss_score, t.kev_status,
       c.peso_normalizacion AS crit, a.exposicion_internet, t.message_id,
       (t.fecha_ingesta_pipeline - interval '3 hours')::date AS corrida_local,
       t.fecha_ingesta_pipeline, t.fecha_alerta_generada
FROM telemetria_vulnerabilidades t
JOIN activos a ON a.id = t.activo_id
JOIN criticidad_niveles c ON c.id = a.criticidad_id;
"""


def consultar(sql):
    cmd = ["docker", "exec", "-i", CONTENEDOR, "sh", "-c",
           'psql -U "$POSTGRES_USER" -d secops_research_db --csv']
    r = subprocess.run(cmd, input=sql, capture_output=True, text=True, encoding="utf-8", check=True)
    return list(csv.DictReader(io.StringIO(r.stdout)))


def indice_escenario(p):
    exp = 1.0 if p["exposicion_internet"] == "t" else 0.0
    kev = 1.0 if p["kev_status"] == "t" else 0.0
    return round(ESCENARIO["cvss"] * float(p["cvss_score"]) / 10 + ESCENARIO["epss"] * float(p["epss_score"])
                 + ESCENARIO["kev"] * kev + ESCENARIO["crit"] * float(p["crit"]) + ESCENARIO["exp"] * exp, 4)


def main():
    pares = consultar(SQL_PARES)
    notif = [p for p in pares if p["estado"] == "NOTIFICADA"]
    resto = [p for p in pares if p["estado"] != "NOTIFICADA"]
    sobre_umbral = [p for p in pares if float(p["irc_score"]) >= UMBRAL]
    con_msgid = [p for p in notif if p["message_id"]]
    assert {(p["cve_id"], p["hostname"]) for p in sobre_umbral} == {(p["cve_id"], p["hostname"]) for p in notif}
    assert not any(p["message_id"] for p in resto)

    max_no_notif = max(resto, key=lambda p: float(p["irc_score"]))
    min_notif = min(notif, key=lambda p: float(p["irc_score"]))
    cercano_esc = max(resto, key=indice_escenario)

    SALIDA.mkdir(parents=True, exist_ok=True)
    resumen = [
        ("pares", len(pares)),
        ("pares_sobre_umbral", len(sobre_umbral)),
        ("notificados", len(notif)),
        ("notificados_con_message_id", len(con_msgid)),
        ("message_id_distintos", len({p["message_id"] for p in con_msgid})),
        ("vulnerabilidades_notificadas", len({p["cve_id"] for p in notif})),
        ("corridas_con_correo", len({p["corrida_local"] for p in notif})),
        ("irc_max_no_notificado", max_no_notif["irc_score"]),
        ("irc_max_no_notificado_par", f'{max_no_notif["cve_id"]} {max_no_notif["hostname"]}'),
        ("irc_min_notificado", min_notif["irc_score"]),
        ("irc_min_notificado_par", f'{min_notif["cve_id"]} {min_notif["hostname"]}'),
        ("escenario_max_no_notificado", indice_escenario(cercano_esc)),
        ("escenario_max_no_notificado_par", f'{cercano_esc["cve_id"]} {cercano_esc["hostname"]}'),
        ("escenario_no_notificados_sobre_umbral", sum(indice_escenario(p) >= UMBRAL for p in resto)),
    ]
    with open(SALIDA / "resumen.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["medida", "valor"])
        w.writerows(resumen)

    corridas = sorted({p["corrida_local"] for p in notif})
    with open(SALIDA / "por_corrida.csv", "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        w.writerow(["corrida_local", "correos", "vulnerabilidades", "activos", "ingesta_utc", "primer_envio_utc"])
        for c in corridas:
            sub = [p for p in notif if p["corrida_local"] == c]
            w.writerow([c, len(sub), len({p["cve_id"] for p in sub}), len({p["hostname"] for p in sub}),
                        min(p["fecha_ingesta_pipeline"] for p in sub),
                        min(p["fecha_alerta_generada"] for p in sub)])

    for fila in resumen:
        print(*fila, sep="\t")
    print(open(SALIDA / "por_corrida.csv", encoding="utf-8").read())


if __name__ == "__main__":
    main()
