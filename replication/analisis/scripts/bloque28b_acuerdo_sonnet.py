"""Bloque 28B -- Acuerdo entre la revision a ciegas de un modelo distinto (Sonnet) y los juicios previos.

Lo pidio la tercera revision independiente (21/10): el kappa de la 5.2.1 compara dos instancias del
mismo modelo. Esta revision la hizo otro modelo, sin acceso a ningun juicio previo, sobre los mismos
65 casos de la via de inferencia y con el criterio de la 5.2 (producto y version, no exposicion).

Categorias: correcto, error y dudoso. El revisor nuevo dejo como dudosos los 43 casos de Windows
Server porque el inventario no registra la compilacion (su regla R1). Se calcula el acuerdo con esa
regla y con la lectura alternativa que el propio revisor informa (esos 43 como correctos).

Fuentes:
  - Revisor nuevo: quality_reports/reviews/2026-10-21_revision_3/muestra_sonnet/revision.csv
  - Juicio final (el que usa la tasa de error): data/cleaned/bloque6_revision_inferencia/propuesta.csv
  - Revision del 04/10 y propuesta previa: igual que scripts/bloque27_acuerdo_revisores.py

Salida: data/cleaned/bloque28b_acuerdo_sonnet/acuerdo.csv y discrepancias.csv
"""
import csv
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
SONNET = RAIZ / "quality_reports" / "reviews" / "2026-10-21_revision_3" / "muestra_sonnet" / "revision.csv"
FINAL = RAIZ / "data" / "cleaned" / "bloque6_revision_inferencia" / "propuesta.csv"
REVISION_0410 = RAIZ / "quality_reports" / "reviews" / "2026-10-04_bloque6_revision_independiente_inferencia.md"
DESTINO = RAIZ / "data" / "cleaned" / "bloque28b_acuerdo_sonnet"

CATEGORIAS = ("correcto", "error", "dudoso")
PREVIA_DISTINTA = {"I63": "error"}   # tabla de contraste de la respuesta del 04/10
WINDOWS_SERVER = {f"I{n}" for n in range(20, 63)}


def categoria(veredicto):
    v = veredicto.strip().lower()
    for c in CATEGORIAS:
        if v.startswith(c):
            return c
    raise ValueError(veredicto)


def kappa(a, b):
    n = len(a)
    po = sum(a[k] == b[k] for k in a) / n
    ma, mb = Counter(a.values()), Counter(b.values())
    pe = sum(ma[c] * mb[c] for c in CATEGORIAS) / n ** 2
    return po, pe, (po - pe) / (1 - pe) if pe < 1 else float("nan")


sonnet = {f["id"]: categoria(f["veredicto"]) for f in csv.DictReader(SONNET.open(encoding="utf-8-sig"))}
sonnet_alt = {k: ("correcto" if k in WINDOWS_SERVER and v == "dudoso" else v) for k, v in sonnet.items()}
final = {f["id"]: ("correcto" if f["par_correcto_propuesto"] == "si" else "error")
         for f in csv.DictReader(FINAL.open(encoding="utf-8"))}
filas = [l.split("|") for l in REVISION_0410.read_text(encoding="utf-8").splitlines() if l.startswith("| I")]
rev0410 = {f[1].strip(): categoria(f[7]) for f in filas}
previa = {k: PREVIA_DISTINTA.get(k, v) for k, v in rev0410.items()}
for d in (sonnet, final, rev0410):
    assert len(d) == 65 and set(d) == set(sonnet), len(d)
assert sonnet_alt.keys() == sonnet.keys()

comparaciones = [
    ("sonnet (R1) vs juicio final", sonnet, final),
    ("sonnet (R1) vs revision 04/10", sonnet, rev0410),
    ("sonnet (R1) vs propuesta previa", sonnet, previa),
    ("sonnet (WS correcto) vs juicio final", sonnet_alt, final),
    ("sonnet (WS correcto) vs revision 04/10", sonnet_alt, rev0410),
    ("sonnet (WS correcto) vs propuesta previa", sonnet_alt, previa),
]
resumen = []
for nombre, a, b in comparaciones:
    po, pe, k = kappa(a, b)
    resumen.append({"comparacion": nombre, "coinciden": sum(a[x] == b[x] for x in a),
                    "acuerdo_observado": round(po, 4), "acuerdo_esperado": round(pe, 4), "kappa": round(k, 4)})

discrepancias = [
    {"id": k, "sonnet": sonnet[k], "juicio_final": final[k], "revision_0410": rev0410[k], "propuesta_previa": previa[k]}
    for k in sorted(sonnet, key=lambda x: int(x[1:]))
    if k not in WINDOWS_SERVER and len({sonnet[k], final[k], rev0410[k], previa[k]}) > 1
]

DESTINO.mkdir(parents=True, exist_ok=True)
for nombre, datos in (("acuerdo.csv", resumen), ("discrepancias.csv", discrepancias)):
    with (DESTINO / nombre).open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(datos[0]))
        w.writeheader()
        w.writerows(datos)

for r in resumen:
    print(r)
for d in discrepancias:
    print(d)
