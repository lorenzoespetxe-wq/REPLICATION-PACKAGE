"""Bloque 28B -- Sensibilidad de la tasa de error de la inferencia a los dos casos en que discrepa la
revision a ciegas de otro modelo (seccion 5.2.2).

Fuera de Windows Server, la revision del 21/10 (Sonnet) coincide con el juicio final salvo en I63
(Node.js, que juzga error) e I08 (Confluence, que deja dudoso). Recalcula la tasa con el metodo del
bloque 11 en tres escenarios: I63 como error; I63 e I08 como error; y los cuatro casos que
resolvieron las reglas de lectura 1 y 3 como error (I08, I63 y los dos de OpenVPN, I64 e I65), que es
el techo de la tasa si todas las dudas de lectura se resuelven en contra. No modifica la salida del
bloque 11.

Entradas (solo lectura): las mismas de scripts/bloque11_precision_inferencia.py
Salida: data/cleaned/bloque28b_sensibilidad_sonnet/tasa_error_escenarios.csv
"""
from bloque11_precision_inferencia import (FIREWALL, MUESTRA, RAIZ, REVISION, WINDOWS,
                                           escribir, leer, tasa)

SALIDA = RAIZ / "data/cleaned/bloque28b_sensibilidad_sonnet"
ESCENARIOS = {"I63 error": {"CVE-2026-48932"},
              "I63 e I08 error": {"CVE-2026-48932", "CVE-2026-21586"},
              "cuatro dudosos error": {"CVE-2026-48932", "CVE-2026-21586", "CVE-2026-81830", "CVE-2026-84256"}}


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)
    veredicto = {(r["cve_id"], r["producto_inventario"]): r for r in leer(REVISION)}
    filas = []
    for escenario, extra in ESCENARIOS.items():
        casos = []
        for m in leer(MUESTRA / "muestra_inferencia.csv"):
            v = veredicto[(m["cve_id"], m["estrato"])]
            error = v["par_correcto_propuesto"] != "si" or m["cve_id"] in extra
            casos.append({"producto": m["estrato"], "peso": float(m["peso_caso"]),
                          "pares": int(m["pares"]), "error": error})
        assert len(casos) == 65 and sum(c["error"] for c in casos) == 5 + len(extra)
        for e in leer(MUESTRA / "errores_conocidos.csv"):
            if e["via"] == "inferencia":
                casos.append({"producto": FIREWALL, "peso": 1.0, "pares": int(e["pares"]), "error": True})
        assert len(casos) == 72
        grupos = {"total": casos,
                  "windows_server": [c for c in casos if c["producto"] in WINDOWS],
                  "resto": [c for c in casos if c["producto"] not in WINDOWS]}
        filas += [{"escenario": escenario, "grupo": nombre, "unidad": unidad, **tasa(sub, por_par)}
                  for nombre, sub in grupos.items()
                  for unidad, por_par in (("caso", False), ("par", True))]
    escribir(SALIDA / "tasa_error_escenarios.csv", filas)
    for f in filas:
        print(f)


if __name__ == "__main__":
    main()
