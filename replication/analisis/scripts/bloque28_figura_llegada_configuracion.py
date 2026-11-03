"""Bloque 28 -- Figura de la llegada de la configuracion de la NVD (apartado 5.4.3).

Dibuja el acumulado de la Tabla 30 como curva continua: que proporcion de las 1.018
vulnerabilidades correlacionadas tenia configuracion publicada a los t dias de su publicacion.
Usa el mismo criterio que scripts/bloque12b_fecha_configuracion.py:156-157:
  - las 922 con fecha del historial de la NVD suman en el dia exacto de su alta;
  - las 47 que ya la tenian en la primera corrida suman en el momento de esa corrida (su cota
    superior: deteccion_formal_horas de bloque12b_latencia_deteccion, entre 20 y 27 horas);
  - las 49 sin configuracion al 3/10 no suman en ningun plazo.
Antes de dibujar, comprueba que la curva reproduzca las seis filas de la Tabla 30.

Sin titulo dentro de la figura: el epigrafe va en paper/main.md.
Entradas: data/cleaned/bloque12b_latencia_deteccion/por_vulnerabilidad.csv (las 1.018) y
data/cleaned/bloque12b_fecha_configuracion/por_vulnerabilidad.csv (las 922 con fecha).
Salida: paper/figures/fig5_llegada_configuracion.png
"""
import csv
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
matplotlib.rcParams["font.family"] = "serif"
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.ticker import FuncFormatter

RAIZ = Path(__file__).resolve().parent.parent
TODAS = RAIZ / "data" / "cleaned" / "bloque12b_latencia_deteccion" / "por_vulnerabilidad.csv"
CON_FECHA = RAIZ / "data" / "cleaned" / "bloque12b_fecha_configuracion" / "por_vulnerabilidad.csv"
SALIDA = RAIZ / "paper" / "figures" / "fig5_llegada_configuracion.png"

VENTANA = 65 / 24  # maximo que una vulnerabilidad permanece en la ventana (seccion 3.7; bloque28c_salida_ventana.py)
TABLA_30 = {3: 302, 5: 391, 7: 459, 10: 630, 14: 749, 21: 932}
TINTA = "#1f2937"
TINTA_SUAVE = "#6b7280"
GRILLA = "#e5e7eb"
FRANJA = "#f3f4f6"

with TODAS.open(encoding="utf-8") as f:
    todas = list(csv.DictReader(f))
with CON_FECHA.open(encoding="utf-8") as f:
    dias_alta = np.array([float(r["dias_publicacion_a_configuracion"]) for r in csv.DictReader(f)])

total = len(todas)
dias_primera = np.array([float(t["deteccion_formal_horas"]) / 24 for t in todas
                         if t["momento_del_dato"] == "primera_corrida"])
primera = len(dias_primera)
sin_dato = total - primera - len(dias_alta)
assert (total, primera, len(dias_alta), sin_dato) == (1018, 47, 922, 49)

dias = np.sort(np.concatenate([dias_primera, dias_alta]))
acumulado = np.arange(1, len(dias) + 1)

for plazo, esperado in TABLA_30.items():
    assert int(np.searchsorted(dias, plazo, side="right")) == esperado, plazo


def pct(n):
    return 100 * n / total


def coma(x, decimales=1):
    return f"{x:.{decimales}f}".replace(".", ",")


fig, ax = plt.subplots(figsize=(6.3, 3.4), dpi=300)
ax.axvspan(0, VENTANA, color=FRANJA, zorder=0)
ax.text(VENTANA / 2, 96, "Ventana\ndel flujo", ha="center", va="top", fontsize=8, color=TINTA_SUAVE)

x = np.concatenate([[0], dias, [25]])
y = np.concatenate([[0], pct(acumulado), [pct(acumulado[-1])]])
ax.step(x, y, where="post", color=TINTA, linewidth=1.6, zorder=3)

for plazo in (3, 14):
    valor = pct(TABLA_30[plazo])
    ax.plot(plazo, valor, "o", markersize=5, color=TINTA, markeredgecolor="white",
            markeredgewidth=1.5, zorder=4)
    ax.annotate(f"{coma(valor)} % a los {plazo} días", (plazo, valor), xytext=(8, -4),
                textcoords="offset points", fontsize=8, color=TINTA, va="top")

ax.text(24.8, 84, f"{coma(pct(sin_dato))} % seguía sin configuración\nal 3 de octubre",
        fontsize=8, color=TINTA_SUAVE, ha="right", va="top")

ax.set_xlim(0, 25)
ax.set_ylim(0, 100)
ax.set_xticks([0, 3, 7, 14, 21])
ax.set_yticks(range(0, 101, 20))
ax.yaxis.set_major_formatter(FuncFormatter(lambda v, _: f"{v:.0f} %"))
ax.set_xlabel("Días desde la publicación", fontsize=9, color=TINTA)
ax.set_ylabel("Con configuración publicada\n(% de las 1.018)", fontsize=9, color=TINTA)
ax.tick_params(labelsize=8, colors=TINTA_SUAVE, length=0)
ax.grid(axis="y", color=GRILLA, linewidth=0.6)
for lado in ("top", "right", "left"):
    ax.spines[lado].set_visible(False)
ax.spines["bottom"].set_color(TINTA_SUAVE)

fig.tight_layout()
SALIDA.parent.mkdir(parents=True, exist_ok=True)
fig.savefig(SALIDA, facecolor="white")
print(f"{SALIDA.relative_to(RAIZ)}: {total} vulnerabilidades, {primera} en la primera corrida, "
      f"{len(dias_alta)} con fecha, {sin_dato} sin configuracion; Tabla 30 reproducida")
