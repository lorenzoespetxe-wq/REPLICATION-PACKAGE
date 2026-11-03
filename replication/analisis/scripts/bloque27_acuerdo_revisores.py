"""Bloque 27 -- Acuerdo entre la propuesta previa y la revision independiente (65 casos de inferencia).

Lo pidio el dictamen de la facultad del 20/10: la seccion 5.2.1 informa solo la proporcion bruta
(61 de 65) y no un estadistico corregido por azar.

Categorias: correcto, error y dudoso (el caso que el revisor no decide). Los subtipos de error
(version, complemento) y de dudoso (plataforma) se agrupan en su categoria.

Fuentes:
  - Veredicto del revisor: columna 8 de la tabla de casos de
    quality_reports/reviews/2026-10-04_bloque6_revision_independiente_inferencia.md.
  - Propuesta previa: coincide con el revisor salvo en los casos que lista la tabla de contraste de
    quality_reports/reviews/2026-10-04_bloque6_respuesta_a_la_revision.md. De ellos, solo I63
    difiere de categoria (la propuesta previa decia error de version; el revisor, dudoso); I08,
    I64 e I65 quedaron como dudoso en los dos juicios.

Salida: data/cleaned/bloque27_acuerdo_revisores/acuerdo.csv
"""
import csv
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parents[1]
REVISION = RAIZ / "quality_reports" / "reviews" / "2026-10-04_bloque6_revision_independiente_inferencia.md"
DESTINO = RAIZ / "data" / "cleaned" / "bloque27_acuerdo_revisores"

PREVIA_DISTINTA = {"I63": "error"}   # tabla de contraste de la respuesta del 04/10


def categoria(veredicto):
    v = veredicto.strip().lower()
    for c in ("correcto", "error", "dudoso"):
        if v.startswith(c):
            return c
    raise ValueError(veredicto)


filas = [l.split("|") for l in REVISION.read_text(encoding="utf-8").splitlines() if l.startswith("| I")]
revisor = {f[1].strip(): categoria(f[7]) for f in filas}
assert len(revisor) == 65, len(revisor)
previa = {k: PREVIA_DISTINTA.get(k, v) for k, v in revisor.items()}

n = len(revisor)
coinciden = sum(previa[k] == revisor[k] for k in revisor)
m_previa, m_revisor = Counter(previa.values()), Counter(revisor.values())
po = coinciden / n
pe = sum(m_previa[c] * m_revisor[c] for c in ("correcto", "error", "dudoso")) / n ** 2
kappa = (po - pe) / (1 - pe)

resumen = [
    {"medida": "casos", "valor": n},
    {"medida": "coinciden en categoria", "valor": coinciden},
    {"medida": "coinciden con veredicto firme (sin dudoso)", "valor": sum(previa[k] == revisor[k] != "dudoso" for k in revisor)},
    {"medida": "acuerdo observado", "valor": round(po, 4)},
    {"medida": "acuerdo esperado por azar", "valor": round(pe, 4)},
    {"medida": "kappa de Cohen", "valor": round(kappa, 4)},
] + [{"medida": f"revisor: {c}", "valor": m_revisor[c]} for c in ("correcto", "error", "dudoso")] \
  + [{"medida": f"previa: {c}", "valor": m_previa[c]} for c in ("correcto", "error", "dudoso")]

DESTINO.mkdir(parents=True, exist_ok=True)
with (DESTINO / "acuerdo.csv").open("w", encoding="utf-8", newline="") as f:
    w = csv.DictWriter(f, fieldnames=["medida", "valor"])
    w.writeheader()
    w.writerows(resumen)
for r in resumen:
    print(f"{r['medida']}: {r['valor']}")
