"""Bloque 9, decision 5: el diseno anterior respetaba la version?

El flujo anterior (workflow "Previous Version") pedia a la NVD, por cada activo,
las vulnerabilidades del identificador completo (cpeName, con version) y no
filtraba nada por su cuenta. Este script verifica, para los 20 identificadores
distintos del inventario, si esa consulta respeta la version y los rangos.

Para cada identificador:
  A = lo que devuelve cpeName con la version del inventario (lo que hacia el flujo).
  B = lo que devuelve virtualMatchString a nivel producto, sin version (todas las
      vulnerabilidades que mencionan el producto en cualquier version).
  Prediccion = el subconjunto de B cuyos criterios declarados (version exacta o
      rango) incluyen la version del inventario, evaluado aca, localmente.
  Si A coincide con la prediccion, el servidor respeta version y rangos.
  B - A = lo que una comparacion solo por fabricante y producto agregaria.
  V = cpeName + isVulnerable: lo que queda si se exige que el producto sea el
      vulnerable y no la plataforma. A - V = coincidencias solo por plataforma.

Solo lectura: base (inventario) y API publica de la NVD. Las respuestas crudas
se guardan en data/raw/nvd_verificacion_version/.

Uso (opcional, mas rapido):  $env:NVD_API_KEY = "<clave>"  (no se escribe en archivos)
"""

import csv
import json
import os
import re
import subprocess
import time
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CRUDO = RAIZ / "data" / "raw" / "nvd_verificacion_version"
SALIDA = RAIZ / "data" / "cleaned" / "bloque9_verificacion_version"
CONTENEDOR = "postgres_db"
URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
POR_PAGINA = 2000

CLAVE = os.environ.get("NVD_API_KEY", "")
PAUSA = 0.8 if CLAVE else 6.5  # limites publicados: 50 o 5 peticiones cada 30 s


def inventario():
    sql = "select distinct cpe from activos order by 1;"
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -At -c "{sql}"']
    return [l for l in subprocess.run(cmd, capture_output=True, text=True, check=True).stdout.split() if l]


def consultar(params, etiqueta):
    """Pagina la respuesta completa; guarda cada pagina cruda."""
    vulns, inicio, pagina = [], 0, 0
    while True:
        guardado = CRUDO / f"{etiqueta}_p{pagina}.json"
        if guardado.exists():  # reanudar sin volver a consultar
            datos = json.loads(guardado.read_text(encoding="utf-8"))
            vulns.extend(datos["vulnerabilities"])
            inicio += POR_PAGINA
            pagina += 1
            if inicio >= datos["totalResults"]:
                return vulns
            continue
        q = dict(params, resultsPerPage=POR_PAGINA, startIndex=inicio)
        url = URL + "?" + urllib.parse.urlencode(q, safe=":*")
        url = url.replace("isVulnerable=True", "isVulnerable")
        req = urllib.request.Request(url, headers={"User-Agent": "Tesis-UTN-verificacion/1.0",
                                                   **({"apiKey": CLAVE} if CLAVE else {})})
        for intento in range(5):
            try:
                with urllib.request.urlopen(req, timeout=120) as r:
                    datos = json.load(r)
                break
            except Exception:
                time.sleep(30 * (intento + 1))
        else:
            raise RuntimeError(f"sin respuesta: {url}")
        (CRUDO / f"{etiqueta}_p{pagina}.json").write_text(json.dumps(datos), encoding="utf-8")
        vulns.extend(datos["vulnerabilities"])
        inicio += POR_PAGINA
        pagina += 1
        time.sleep(PAUSA)
        if inicio >= datos["totalResults"]:
            return vulns


def fichas(v):
    return re.findall(r"\d+|[a-z]+", v.lower())


def comparar(a, b):
    """-1, 0, 1; None si mezcla numeros y letras en la misma posicion."""
    ta, tb = fichas(a), fichas(b)
    for x, y in zip(ta, tb):
        if x == y:
            continue
        if x.isdigit() and y.isdigit():
            return -1 if int(x) < int(y) else 1
        if x.isdigit() != y.isdigit():
            return None
        return -1 if x < y else 1
    return (len(ta) > len(tb)) - (len(ta) < len(tb))


def componente_ok(crit, inv):
    # "*" en el inventario significa cualquier valor (p. ej. cualquier edicion)
    return inv == "*" or crit in ("*", inv)


def criterio_incluye(m, inv):
    """True/False si el criterio declarado incluye el CPE del inventario; None si ambiguo."""
    c, i = m["criteria"].split(":"), inv.split(":")
    if c[2:5] != i[2:5]:
        return False
    for k in range(6, 13):
        if not componente_ok(c[k], i[k]):
            return False
    ver, cv = i[5], c[5]
    hay_rango = any(k in m for k in ("versionStartIncluding", "versionStartExcluding",
                                     "versionEndIncluding", "versionEndExcluding"))
    if cv != "*":
        return cv == ver
    if not hay_rango:
        return True
    if ver in ("-", "*"):
        return None
    for k, ok in (("versionStartIncluding", (0, 1)), ("versionStartExcluding", (1,)),
                  ("versionEndIncluding", (-1, 0)), ("versionEndExcluding", (-1,))):
        if k in m:
            r = comparar(ver, m[k])
            if r is None:
                return None
            if r not in ok:
                return False
    return True


def prediccion(v, inv):
    """Incluida si algun criterio (vulnerable o no) incluye el CPE del inventario."""
    resultados = []
    for conf in v["cve"].get("configurations", []):
        for nodo in conf["nodes"]:
            for m in nodo["cpeMatch"]:
                resultados.append(criterio_incluye(m, inv))
    if True in resultados:
        return True
    if None in resultados:
        return None
    return False


def main():
    CRUDO.mkdir(parents=True, exist_ok=True)
    SALIDA.mkdir(parents=True, exist_ok=True)
    cpes = inventario()
    filas = [None] * len(cpes)
    detalle = []
    for n, inv in enumerate(cpes):
        nombre = re.sub(r"[^a-z0-9]+", "_", ":".join(inv.split(":")[3:6]).lower())
        producto = ":".join(inv.split(":")[:5])
        a = {v["cve"]["id"] for v in consultar({"cpeName": inv}, f"{nombre}_A_cpeName")}
        b_lista = consultar({"virtualMatchString": producto}, f"{nombre}_B_producto")
        vset = {v["cve"]["id"] for v in consultar({"cpeName": inv, "isVulnerable": True}, f"{nombre}_V_isVulnerable")}
        b = {v["cve"]["id"] for v in b_lista}
        pred = {v["cve"]["id"]: prediccion(v, inv) for v in b_lista}
        si = {k for k, p in pred.items() if p is True}
        ambiguas = {k for k, p in pred.items() if p is None}
        en_a_no_pred = (a - si) - ambiguas
        en_pred_no_a = si - a
        for k in sorted(en_a_no_pred | en_pred_no_a | ambiguas):
            detalle.append({"cpe_inventario": inv, "cve_id": k,
                            "devuelto_por_cpeName": k in a,
                            "prediccion_local": pred.get(k, "fuera de B")})
        filas[n] = {
            "cpe_inventario": inv,
            "B_producto_cualquier_version": len(b),
            "A_cpeName_con_version": len(a),
            "prediccion_local_por_rangos": len(si),
            "ambiguas_sin_decidir_localmente": len(ambiguas),
            "coinciden_A_y_prediccion": len(a & si),
            "A_no_predichas": len(en_a_no_pred),
            "predichas_no_en_A": len(en_pred_no_a),
            "A_fuera_de_B": len(a - b),
            "excluidas_por_version_B_menos_A": len(b - a),
            "V_isVulnerable": len(vset),
            "solo_plataforma_A_menos_V": len(a - vset),
        }
        print(filas[n])
    campos = list(filas[0].keys())
    with open(SALIDA / "verificacion_por_identificador.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=campos)
        w.writeheader()
        w.writerows(filas)
    with open(SALIDA / "discrepancias.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["cpe_inventario", "cve_id", "devuelto_por_cpeName", "prediccion_local"])
        w.writeheader()
        w.writerows(detalle)
    (SALIDA / "registro.txt").write_text(
        f"Ejecutado {datetime.now(timezone.utc).isoformat()} UTC; {len(cpes)} identificadores; "
        f"clave de API: {'si' if CLAVE else 'no'}\n", encoding="utf-8")


if __name__ == "__main__":
    main()
