"""Bloque 27 -- Sensibilidad de la tasa de error de la inferencia al criterio de OpenVPN (seccion 5.2.2).

Lo pidio el dictamen de la facultad del 20/10: los dos casos de OpenVPN (I64, I65) se juzgaron
correctos por decision del autor del 11/10, apartandose de la revision independiente, que los
juzgaba error de plataforma. La seccion 5.2.2 informa la sensibilidad a un caso de Jenkins, pero
no a este criterio.

Recalcula la tasa con el mismo metodo del bloque 11 (ponderacion, Korn-Graubard), contando I64 e
I65 como error. No modifica la salida del bloque 11.

Entradas (solo lectura): las mismas de scripts/bloque11_precision_inferencia.py
Salida: data/cleaned/bloque27_sensibilidad_openvpn/tasa_error_openvpn_error.csv
"""
from bloque11_precision_inferencia import (FIREWALL, MUESTRA, RAIZ, REVISION, WINDOWS,
                                           escribir, leer, tasa)

SALIDA = RAIZ / "data/cleaned/bloque27_sensibilidad_openvpn"
OPENVPN = {"CVE-2026-81830", "CVE-2026-84256"}   # I64, I65


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)
    veredicto = {(r["cve_id"], r["producto_inventario"]): r for r in leer(REVISION)}
    casos = []
    for m in leer(MUESTRA / "muestra_inferencia.csv"):
        v = veredicto[(m["cve_id"], m["estrato"])]
        error = v["par_correcto_propuesto"] != "si" or m["cve_id"] in OPENVPN
        casos.append({"producto": m["estrato"], "peso": float(m["peso_caso"]),
                      "pares": int(m["pares"]), "error": error})
    assert len(casos) == 65
    assert sum(c["error"] for c in casos) == 7, "esperados 5 errores del bloque 6 mas los 2 de OpenVPN"
    for e in leer(MUESTRA / "errores_conocidos.csv"):
        if e["via"] == "inferencia":
            casos.append({"producto": FIREWALL, "peso": 1.0, "pares": int(e["pares"]), "error": True})
    assert len(casos) == 72

    grupos = {"total": casos,
              "windows_server": [c for c in casos if c["producto"] in WINDOWS],
              "resto": [c for c in casos if c["producto"] not in WINDOWS]}
    filas = [{"grupo": nombre, "unidad": unidad, **tasa(sub, por_par)}
             for nombre, sub in grupos.items()
             for unidad, por_par in (("caso", False), ("par", True))]
    escribir(SALIDA / "tasa_error_openvpn_error.csv", filas)
    for f in filas:
        print(f)


if __name__ == "__main__":
    main()
