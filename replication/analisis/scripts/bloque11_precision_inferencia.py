"""Bloque 11 -- Tasa ponderada de error de la via de inferencia (seccion 5.2.2).

Combina el veredicto final de los 65 casos sorteados (bloque 6) con los 7 casos del firewall,
que quedaron fuera del sorteo porque ya se sabian falsos positivos y se suman como censo.

Ponderacion:
  - Cada caso sorteado pesa casos_del_producto / casos_sorteados_del_producto (peso_caso del
    bloque 5). Cada caso del firewall pesa 1 (se revisaron todos).
  - Tasa por caso: suma de pesos de los casos con error / suma de pesos.
  - Tasa por par: igual, multiplicando cada peso por los pares del caso (un caso de Windows
    Server 2019 o 2022 y de macOS abarca dos activos).

Intervalo al 95 %: Korn-Graubard. Se calcula la varianza del diseno estratificado, con
correccion por poblacion finita; los productos revisados completos (firewall, Confluence,
Node.js) aportan varianza cero. De ahi sale un tamano efectivo, n_ef = p(1-p)/V, topeado en
los casos revisados, y sobre el se aplica el intervalo exacto de Clopper-Pearson. Cuando no hay
ningun error (p = 0), n_ef = casos revisados. Se eligio frente a la varianza estratificada con
aproximacion normal porque en ocho de los doce productos no hubo ningun error y esa varianza
da cero en ellos; y frente a Wilson sobre el tamano efectivo de Kish (version anterior de este
script) porque Kish supone que el error no depende del peso, y aqui se concentra en los
productos chicos. Revision: quality_reports/reviews/2026-10-11_bloque11_revision_tasa_error.md.
Tambien se informa el intervalo de Wilson-Kish, como contraste.

La separacion Windows Server / resto no estaba declarada en el sorteo: se decidio en la
revision del bloque 6, despues de ver los errores. Es descriptiva.

Entradas (solo lectura):
  data/cleaned/bloque5_muestra_validacion/muestra_inferencia.csv, asignacion_inferencia.csv,
  errores_conocidos.csv; data/cleaned/bloque6_revision_inferencia/propuesta.csv
Salida: data/cleaned/bloque11_precision_inferencia/ (sin titulos ni notas)
  tasa_error.csv, error_por_producto.csv
"""
import csv
import math
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
MUESTRA = RAIZ / "data/cleaned/bloque5_muestra_validacion"
REVISION = RAIZ / "data/cleaned/bloque6_revision_inferencia/propuesta.csv"
SALIDA = RAIZ / "data/cleaned/bloque11_precision_inferencia"
Z = 1.959964
WINDOWS = {"microsoft:windows_server_2016", "microsoft:windows_server_2019",
           "microsoft:windows_server_2022"}
FIREWALL = "cisco:ios"


def leer(ruta):
    with open(ruta, encoding="utf-8", newline="") as f:
        return list(csv.DictReader(f))


def escribir(ruta, filas):
    with open(ruta, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0].keys()))
        w.writeheader()
        w.writerows(filas)


def wilson(p, n):
    """Intervalo de Wilson al 95 % para una proporcion p con tamano (efectivo) n."""
    den = 1 + Z * Z / n
    centro = (p + Z * Z / (2 * n)) / den
    medio = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / den
    return max(0.0, centro - medio), min(1.0, centro + medio)


def _beta_cf(a, b, x):
    """Fraccion continua de la beta incompleta (Numerical Recipes, betacf)."""
    qab, qap, qam = a + b, a + 1, a - 1
    c, d = 1.0, 1 - qab * x / qap
    d = 1 / (d if abs(d) > 1e-300 else 1e-300)
    h = d
    for m in range(1, 300):
        m2 = 2 * m
        for aa in (m * (b - m) * x / ((qam + m2) * (a + m2)),
                   -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))):
            d = 1 + aa * d
            d = 1 / (d if abs(d) > 1e-300 else 1e-300)
            c = 1 + aa / c
            c = c if abs(c) > 1e-300 else 1e-300
            h *= d * c
        if abs(d * c - 1) < 1e-14:
            break
    return h


def beta_inc(a, b, x):
    """Funcion beta incompleta regularizada I_x(a, b)."""
    if x <= 0:
        return 0.0
    if x >= 1:
        return 1.0
    ln = math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1 - x)
    if x < (a + 1) / (a + b + 2):
        return math.exp(ln) * _beta_cf(a, b, x) / a
    return 1 - math.exp(ln) * _beta_cf(b, a, 1 - x) / b


def beta_ppf(q, a, b):
    """Cuantil de la distribucion beta, por biseccion."""
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = (lo + hi) / 2
        if beta_inc(a, b, mid) < q:
            lo = mid
        else:
            hi = mid
    return (lo + hi) / 2


def clopper_pearson(x, n):
    """Intervalo exacto al 95 %; x puede no ser entero (x = p * n_ef)."""
    li = 0.0 if x <= 0 else beta_ppf(0.025, x, n - x + 1)
    ls = 1.0 if x >= n else beta_ppf(0.975, x + 1, n - x)
    return li, ls


def tasa(casos, por_par):
    """casos: lista de dicts con producto, peso, pares, error. Devuelve fila de resultado."""
    w = [c["peso"] * (c["pares"] if por_par else 1) for c in casos]
    total = sum(w)
    err = sum(wi for wi, c in zip(w, casos) if c["error"])
    p = err / total
    n = len(casos)
    # Korn-Graubard: varianza del diseno estratificado con correccion por poblacion finita
    var = 0.0
    for prod in {c["producto"] for c in casos}:
        sub = [(wi, c) for wi, c in zip(w, casos) if c["producto"] == prod]
        n_h = len(sub)
        tam_h = sum(wi for wi, _ in sub)            # tamano del producto en la unidad elegida
        casos_h = sum(c["peso"] for _, c in sub)    # casos del producto en el universo
        if n_h >= casos_h - 1e-9 or n_h < 2:        # revisado completo: sin varianza
            continue
        p_h = sum(c["error"] for _, c in sub) / n_h
        s2 = n_h / (n_h - 1) * p_h * (1 - p_h)
        var += (tam_h / total) ** 2 * (1 - n_h / casos_h) * s2 / n_h
    n_ef = n if p in (0.0, 1.0) or var == 0 else min(n, p * (1 - p) / var)
    li, ls = clopper_pearson(p * n_ef, n_ef)
    # contraste: Wilson sobre el tamano efectivo de Kish (version anterior)
    n_kish = total ** 2 / sum(wi * wi for wi in w)
    wli, wls = wilson(p, n_kish)
    return {"revisados": n, "errores_revisados": sum(c["error"] for c in casos),
            "universo_estimado": round(total), "errores_estimados": round(err, 1),
            "tasa": round(p, 4), "n_efectivo": round(n_ef, 1),
            "ic95_inf": round(li, 4), "ic95_sup": round(ls, 4),
            "wilson_kish_inf": round(wli, 4), "wilson_kish_sup": round(wls, 4)}


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)
    veredicto = {(r["cve_id"], r["producto_inventario"]): r for r in leer(REVISION)}
    casos = []
    for m in leer(MUESTRA / "muestra_inferencia.csv"):
        v = veredicto[(m["cve_id"], m["estrato"])]
        casos.append({"producto": m["estrato"], "peso": float(m["peso_caso"]),
                      "pares": int(m["pares"]), "error": v["par_correcto_propuesto"] != "si",
                      "tipo": v["tipo_error_propuesto"]})
    assert len(casos) == 65
    for e in leer(MUESTRA / "errores_conocidos.csv"):
        if e["via"] == "inferencia":
            casos.append({"producto": FIREWALL, "peso": 1.0, "pares": int(e["pares"]),
                          "error": True, "tipo": "coincidencia parcial de nombre"})
    assert len(casos) == 72
    # control: los pesos reconstruyen el universo del bloque 5 (2.025 casos, 3.424 pares)
    assert round(sum(c["peso"] for c in casos)) == 2025
    assert round(sum(c["peso"] * c["pares"] for c in casos)) == 3424

    grupos = {"total": casos,
              "windows_server": [c for c in casos if c["producto"] in WINDOWS],
              "resto": [c for c in casos if c["producto"] not in WINDOWS],
              "total_sin_firewall": [c for c in casos if c["producto"] != FIREWALL]}
    filas = []
    for nombre, sub in grupos.items():
        for unidad, por_par in (("caso", False), ("par", True)):
            filas.append({"grupo": nombre, "unidad": unidad, **tasa(sub, por_par)})
    escribir(SALIDA / "tasa_error.csv", filas)

    universo = {a["estrato"]: a for a in leer(MUESTRA / "asignacion_inferencia.csv")}
    por_prod = []
    for prod in sorted({c["producto"] for c in casos},
                       key=lambda p: (-sum(c["peso"] for c in casos if c["producto"] == p), p)):
        sub = [c for c in casos if c["producto"] == prod]
        tipos = sorted({c["tipo"] for c in sub if c["error"]})
        por_prod.append({"producto": prod,
                         "casos_universo": universo[prod]["casos_universo"] if prod in universo else len(sub),
                         "revisados": len(sub), "errores": sum(c["error"] for c in sub),
                         "tipos_error": "; ".join(tipos)})
    escribir(SALIDA / "error_por_producto.csv", por_prod)
    for f in filas:
        print(f)
    for f in por_prod:
        print(f)


if __name__ == "__main__":
    main()
