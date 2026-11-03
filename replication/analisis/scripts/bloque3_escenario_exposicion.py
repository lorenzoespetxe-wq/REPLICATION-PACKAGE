"""Bloque 3 -- Escenario alternativo de pesos: exposicion a Internet duplicada.

El indice del artefacto usa los pesos 0,15 (severidad), 0,25 (probabilidad de explotacion),
0,30 (explotacion confirmada), 0,20 (criticidad) y 0,10 (exposicion). La exposicion es el peso
con menos respaldo en la literatura revisada (seccion 3.6), de modo que el escenario lo duplica
a 0,20 y descuenta 0,025 de cada uno de los otros cuatro para que la suma siga siendo 1.

Se recalcula el indice de todos los pares persistidos dos veces: con los valores registrados al
detectar (los que el sistema uso para decidir) y con los recalculados al cierre por la reevaluacion
del 01/10 (columnas *_final). En cada caso se compara la decision de notificar (indice >= 0,40) y la
prioridad. Antes se comprueba que la formula reproduce el indice guardado en la base.

Entradas: base de datos (solo lectura).
Salidas:  data/cleaned/bloque3_escenario_exposicion/resumen.csv
          data/cleaned/bloque3_escenario_exposicion/por_grupo.csv
"""
import csv
import subprocess
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SALIDA = RAIZ / "data" / "cleaned" / "bloque3_escenario_exposicion"
CONTENEDOR = "postgres_db"

# orden: severidad, probabilidad de explotacion, explotacion confirmada, criticidad, exposicion
PESOS_ORIGINALES = (0.15, 0.25, 0.30, 0.20, 0.10)
PESOS_ESCENARIO = (0.125, 0.225, 0.275, 0.175, 0.20)
UMBRAL_ALTA = 0.40
UMBRAL_CRITICA = 0.70
TOLERANCIA_REPRODUCCION = 0.00005 + 1e-9  # el indice se guarda con cuatro decimales
MOMENTOS = ("deteccion", "cierre")  # valores al detectar y recalculados al cierre (bloque 2)


def psql(sql):
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -At -F "," -c "{sql}"']
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout


def indice(pesos, fila):
    return sum(w * v for w, v in zip(pesos, fila))


def prioridad(irc):
    if irc >= UMBRAL_CRITICA:
        return "CRITICA"
    return "ALTA" if irc >= UMBRAL_ALTA else "INFORMATIVA"


def leer(momento):
    sufijo = "" if momento == "deteccion" else "_final"
    sql = (f"select t.id, t.irc_score{sufijo}, t.cvss_score{sufijo} / 10.0, t.epss_score{sufijo}, "
           f"t.kev_status{sufijo}::int, n.peso_normalizacion, a.exposicion_internet::int "
           "from telemetria_vulnerabilidades t join activos a on a.id = t.activo_id "
           "join criticidad_niveles n on n.id = a.criticidad_id order by t.id")
    return [[float(x) for x in l.split(",")] for l in psql(sql).strip().splitlines()]


def main():
    assert abs(sum(PESOS_ESCENARIO) - 1) < 1e-9
    SALIDA.mkdir(parents=True, exist_ok=True)
    resumen = csv.writer(open(SALIDA / "resumen.csv", "w", newline="", encoding="utf-8"))
    resumen.writerow(["momento", "pesos", "pares", "notificados", "critica", "alta", "informativa",
                      "entran", "salen", "cambian_prioridad"])
    por_grupo = csv.writer(open(SALIDA / "por_grupo.csv", "w", newline="", encoding="utf-8"))
    por_grupo.writerow(["momento", "expuesto", "kev", "criticidad_norm", "pares", "irc_max_original",
                        "irc_max_escenario", "notificados_original", "notificados_escenario"])

    for momento in MOMENTOS:
        filas = leer(momento)
        error_max = max(abs(indice(PESOS_ORIGINALES, f[2:]) - f[1]) for f in filas)
        assert error_max <= TOLERANCIA_REPRODUCCION, f"{momento}: la formula no reproduce la base: {error_max}"

        orig = [indice(PESOS_ORIGINALES, f[2:]) for f in filas]
        alt = [indice(PESOS_ESCENARIO, f[2:]) for f in filas]
        entran = sum(o < UMBRAL_ALTA <= a for o, a in zip(orig, alt))
        salen = sum(a < UMBRAL_ALTA <= o for o, a in zip(orig, alt))
        cambian = sum(prioridad(o) != prioridad(a) for o, a in zip(orig, alt))
        for pesos, valores in (("original", orig), ("escenario", alt)):
            c = {p: sum(prioridad(v) == p for v in valores) for p in ("CRITICA", "ALTA", "INFORMATIVA")}
            resumen.writerow([momento, pesos, len(filas), c["CRITICA"] + c["ALTA"], c["CRITICA"],
                              c["ALTA"], c["INFORMATIVA"], entran, salen, cambian])

        grupos = {}
        for f, o, a in zip(filas, orig, alt):
            g = grupos.setdefault((int(f[6]), int(f[4]), f[5]), [0, 0.0, 0.0, 0, 0])
            g[0] += 1
            g[1], g[2] = max(g[1], o), max(g[2], a)
            g[3] += o >= UMBRAL_ALTA
            g[4] += a >= UMBRAL_ALTA
        for k in sorted(grupos):
            g = grupos[k]
            por_grupo.writerow([momento, *k, g[0], round(g[1], 4), round(g[2], 4), g[3], g[4]])

        print(f"[{momento}] pares: {len(filas)} | error maximo de reproduccion: {error_max:.6f}")
        print(f"  notificados original: {sum(o >= UMBRAL_ALTA for o in orig)} "
              f"| escenario: {sum(a >= UMBRAL_ALTA for a in alt)}")
        print(f"  criticos original: {sum(o >= UMBRAL_CRITICA for o in orig)} "
              f"| escenario: {sum(a >= UMBRAL_CRITICA for a in alt)}")
        print(f"  entran: {entran} | salen: {salen} | cambian de prioridad: {cambian}")
        print(f"  pares sobre activos expuestos: {sum(1 for f in filas if f[6] == 1)}")
        print(f"  indice maximo de un informativo en el escenario: {max(a for a in alt if a < UMBRAL_ALTA):.4f} "
              f"| minimo de un notificado: {min(a for a in alt if a >= UMBRAL_ALTA):.4f}")


if __name__ == "__main__":
    main()
