"""Bloque 28C -- Cuantas horas despues de su publicacion sale cada vulnerabilidad de la ventana.

La ventana abarca tres dias de calendario en tiempo universal y el flujo corre a las 17:00 UTC
(14:00 locales), seccion 3.7. Una vulnerabilidad publicada antes de las 17:00 UTC de su dia entra
en tres corridas; una publicada despues, en dos. La ultima corrida que la incluye es la del segundo
dia posterior, de modo que sale de la ventana entre 41 y 48 horas despues (publicada despues de las
17:00) o entre 48 y 65 horas despues (publicada antes).

Mide la salida sobre las 788 vulnerabilidades cuya configuracion llego despues de la ventana: su
cota_inferior_utc es la ultima corrida que las vio sin configuracion, es decir, la ultima que las
incluyo. Comprueba que cada una caiga en el tramo que le corresponde por su hora de publicacion.

Entrada: data/cleaned/bloque12b_fecha_configuracion/por_vulnerabilidad.csv
Salida: data/cleaned/bloque28c_salida_ventana/resumen.csv
"""
import csv
import statistics
from datetime import datetime
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ENTRADA = RAIZ / "data" / "cleaned" / "bloque12b_fecha_configuracion" / "por_vulnerabilidad.csv"
SALIDA = RAIZ / "data" / "cleaned" / "bloque28c_salida_ventana" / "resumen.csv"
HORA_CORRIDA_UTC = 17

with ENTRADA.open(encoding="utf-8") as f:
    filas = [r for r in csv.DictReader(f) if r["grupo"] == "despues_de_la_ventana"]

publicacion = [datetime.fromisoformat(r["publicacion_utc"]) for r in filas]
salida = [datetime.fromisoformat(r["cota_inferior_utc"]) for r in filas]
horas = [(s - p).total_seconds() / 3600 for p, s in zip(publicacion, salida)]
antes = [p.hour < HORA_CORRIDA_UTC for p in publicacion]

assert len(horas) == 788
assert all(41 <= h <= 65 for h in horas)
# Una sola cae fuera del tramo de su hora de publicacion: CVE-2026-56143, publicada el 1/09 a las
# 20:17 UTC, la vio por ultima vez la corrida manual del 2/09 local, ejecutada a las 01:29 UTC del
# 3/09 (seccion 3.8), fuera de la hora programada.
fuera_de_tramo = [r["cve_id"] for r, h, a in zip(filas, horas, antes)
                  if not ((48 <= h <= 65) if a else (41 <= h <= 48))]
assert fuera_de_tramo == ["CVE-2026-56143"], fuera_de_tramo

resultado = [
    ("vulnerabilidades que salieron de la ventana sin configuracion", "vulnerabilidades", len(horas)),
    ("publicadas antes de la hora de la corrida (tres corridas)", "vulnerabilidades", sum(antes)),
    ("publicadas despues de la hora de la corrida (dos corridas)", "vulnerabilidades", len(horas) - sum(antes)),
    ("fuera del tramo de su hora de publicacion (corrida manual del 2/09)", "vulnerabilidades",
     len(fuera_de_tramo)),
    ("salida de la ventana, minimo", "horas desde la publicacion", round(min(horas), 1)),
    ("salida de la ventana, mediana", "horas desde la publicacion", round(statistics.median(horas), 1)),
    ("salida de la ventana, maximo", "horas desde la publicacion", round(max(horas), 1)),
]

SALIDA.parent.mkdir(parents=True, exist_ok=True)
with SALIDA.open("w", newline="", encoding="utf-8") as f:
    escritor = csv.writer(f)
    escritor.writerow(["medida", "unidad", "valor", "script"])
    for medida, unidad, valor in resultado:
        escritor.writerow([medida, unidad, valor, "bloque28c_salida_ventana.py"])

for medida, unidad, valor in resultado:
    print(f"{medida}: {valor} {unidad}")
