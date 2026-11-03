"""Bloque 11 -- Las diecisiete notificaciones de la campana y su juicio (seccion 5.2.4).

Lee de la base los pares notificados, reconstruye el indice con los pesos de la seccion 3.6
(control: debe coincidir con el guardado) y agrega el estado de cada vulnerabilidad en la foto
de la NVD del 03/10 y el juicio sobre el par.

Juicio (criterio de la seccion 5.2):
  - Cisco IOS XR sobre fw-edge-01: falso, otro producto del mismo fabricante (los registros de la
    CNA declaran "Cisco IOS XR Software"; el inventario, Cisco IOS 15.4).
  - CVE-2026-85706 sobre srv-git-repo: falso por version. El registro de la CNA declara afectadas
    las ramas desde la 18.7; el inventario, GitLab 16.0.0.
  - CVE-2026-85880 sobre los nueve Windows: producto correcto, version no verificable (el
    inventario no registra el numero de actualizacion).

Entradas: base (solo lectura), data/raw/nvd_reconsulta/configs_vulnerable_20261003.csv,
          data/raw/cvelistv5_cierre/cves/
Salida:   data/cleaned/bloque11_precision_inferencia/notificaciones.csv (sin titulos ni notas)
"""
import csv
import io
import json
import subprocess
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
FOTO_NVD = RAIZ / "data/raw/nvd_reconsulta/configs_vulnerable_20261003.csv"
CORPUS = RAIZ / "data/raw/cvelistv5_cierre/cves"
SALIDA = RAIZ / "data/cleaned/bloque11_precision_inferencia/notificaciones.csv"
CONTENEDOR = "postgres_db"
PESOS = {"cvss": 0.15, "epss": 0.25, "kev": 0.30, "crit": 0.20, "exp": 0.10}  # seccion 3.6

SQL = """
SELECT a.hostname, a.cpe, t.cve_id, t.fuente_correlacion, t.fuente_correlacion_final,
       t.cvss_score, t.epss_score, t.kev_status, t.irc_score, t.prioridad,
       t.fecha_alerta_generada
FROM telemetria_vulnerabilidades t JOIN activos a ON a.id = t.activo_id
WHERE t.estado = 'NOTIFICADA'
ORDER BY t.cve_id, a.hostname;
"""
# criticidad normalizada y exposicion de cada activo, tal como las lee el flujo
SQL_ACTIVOS = """
SELECT a.hostname, c.peso_normalizacion AS crit, a.exposicion_internet
FROM activos a JOIN criticidad_niveles c ON c.id = a.criticidad_id;
"""


def consultar(sql):
    cmd = ["docker", "exec", "-i", CONTENEDOR, "sh", "-c",
           'psql -U "$POSTGRES_USER" -d secops_research_db --csv']
    r = subprocess.run(cmd, input=sql, capture_output=True, text=True, encoding="utf-8", check=True)
    return list(csv.DictReader(io.StringIO(r.stdout)))


def productos_cna(cve):
    ruta = next(CORPUS.rglob(f"{cve}.json"))
    cna = json.loads(ruta.read_text(encoding="utf-8"))["containers"]["cna"]
    return "; ".join(f"{a.get('vendor')} {a.get('product')}" for a in cna.get("affected", []))


def juicio(hostname, cve):
    if hostname == "fw-edge-01":
        return "falso", "otro producto del mismo fabricante (Cisco IOS XR)"
    if cve == "CVE-2026-85706":
        return "falso", "version: afecta desde la 18.7, inventario 16.0.0"
    if cve == "CVE-2026-85880":
        return "producto correcto", "version no verificable (Windows sin numero de actualizacion)"
    raise ValueError(f"notificacion sin juicio: {hostname} {cve}")


def main():
    notif = consultar(SQL)
    assert len(notif) == 17
    activos = {a["hostname"]: a for a in consultar(SQL_ACTIVOS)}
    with open(FOTO_NVD, encoding="utf-8", newline="") as f:
        foto = {r["cve_id"]: r for r in csv.DictReader(f)}
    filas = []
    for n in notif:
        a = activos[n["hostname"]]
        exp = 1.0 if a["exposicion_internet"] == "t" else 0.0
        irc = (PESOS["cvss"] * float(n["cvss_score"]) / 10 + PESOS["epss"] * float(n["epss_score"])
               + PESOS["kev"] * (n["kev_status"] == "t") + PESOS["crit"] * float(a["crit"])
               + PESOS["exp"] * exp)
        assert abs(irc - float(n["irc_score"])) < 6e-4, (n, irc)
        v, motivo = juicio(n["hostname"], n["cve_id"])
        nvd = foto.get(n["cve_id"], {})
        filas.append({"cve_id": n["cve_id"], "hostname": n["hostname"], "cpe_inventario": n["cpe"],
                      "via": n["fuente_correlacion"], "via_final": n["fuente_correlacion_final"],
                      "cvss": n["cvss_score"], "epss": n["epss_score"], "kev": n["kev_status"],
                      "criticidad": a["crit"], "expuesto": int(exp), "irc": n["irc_score"],
                      "alerta": n["fecha_alerta_generada"], "productos_cna": productos_cna(n["cve_id"]),
                      "nvd_estado_0310": nvd.get("vuln_status", ""),
                      "nvd_vulnerables_0310": " ".join(sorted({c.split(":")[3] + ":" + c.split(":")[4]
                                                               for c in nvd.get("cpes_vulnerables", "").split()})),
                      "juicio": v, "motivo": motivo})
    with open(SALIDA, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0].keys()))
        w.writeheader()
        w.writerows(filas)
    for r in filas:
        print(r["cve_id"], r["hostname"], r["via"], r["kev"], r["irc"], r["nvd_estado_0310"],
              r["nvd_vulnerables_0310"], r["juicio"])


if __name__ == "__main__":
    main()
