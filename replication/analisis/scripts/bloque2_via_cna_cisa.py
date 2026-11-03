"""Bloque 2 -- Vias de correlacion que no pasan por el artefacto: identificador de la CNA y CISA.

Mide, sobre el corpus local de registros CVE fijado al cierre de la campana, cuantas de las
vulnerabilidades que el flujo ingirio habrian correlacionado con el inventario si el dato
formal se hubiera tomado del bloque de la CNA (`containers.cna.affected[].cpes` o `containers.cna.cpeApplicability`) o del bloque de
CISA (`containers.adp` con `shortName == "CISA-ADP"`).

El criterio de comparacion replica el de la via formal del artefacto (nodo `Parse NVD Response`
del flujo congelado): se compara el fabricante y el producto del CPE de cada activo contra los de
cada CPE del registro, con y sin version, normalizados igual que alli. Esa comparacion hereda la
ceguera de rangos de version de la via formal, y la ceguera a la plataforma.

Entradas:
  - data/raw/cvelistv5_cierre/        corpus cvelistV5, etiqueta cve_2026-09-27_at_end_of_day
  - data/raw/estado_al_ingerir.csv    vulnerabilidades que el flujo ingirio (bloque 1)
  - data/raw/activos_inventario.csv   inventario de 30 activos
  - base de datos (solo lectura)      pares persistidos por el artefacto, para medir solapamiento

Salidas (data/cleaned/bloque2_vias_cna_cisa/):
  - pares_via_cna.csv       un renglon por par vulnerabilidad-activo que la via de la CNA habria correlacionado
  - resumen_vias.csv        cifras agregadas, con la unidad de computo de cada una
  - no_medidas.csv          vulnerabilidades ingeridas que no estan en el corpus descargado
"""
import csv
import json
import re
import subprocess
from collections import Counter
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CORPUS = RAIZ / "data" / "raw" / "cvelistv5_cierre" / "cves"
INGERIDOS = RAIZ / "data" / "raw" / "estado_al_ingerir.csv"
INVENTARIO = RAIZ / "data" / "raw" / "activos_inventario.csv"
SALIDA = RAIZ / "data" / "cleaned" / "bloque2_vias_cna_cisa"
CONTENEDOR = "postgres_db"


def palabras(*campos):
    """Misma funcion que el artefacto: minusculas, separa en _ - . y espacios, ordena, une con |."""
    texto = "_".join(campos).lower()
    toks = [t for t in re.split(r"[_\-.\s]+", texto) if t and t != "*"]
    return "|".join(sorted(toks))


def claves_cpe(cpe):
    """Devuelve (clave fabricante+producto, clave fabricante+producto+version), o None si no se reconoce.

    Acepta CPE 2.3 (`cpe:2.3:a:vendor:product:version`) y el formato anterior (`cpe:/a:vendor:product:version`),
    igual que el artefacto.
    """
    p = str(cpe or "").split(":")
    if len(p) < 2:
        return None
    if p[1] == "2.3" and len(p) >= 5:
        vendor, product = p[3], p[4]
        version = p[5] if len(p) > 5 else "*"
    elif p[1].startswith("/") and len(p) >= 4:
        vendor, product = p[2], p[3]
        version = p[4] if len(p) > 4 else "*"
    else:
        return None
    return palabras(vendor, product), palabras(vendor, product, version)


def _criterios(nodos):
    """Recorre los nodos de `cpeApplicability` (con sus hijos) y devuelve los CPE de `cpeMatch`."""
    for nodo in nodos:
        for m in nodo.get("cpeMatch", []):
            if m.get("criteria"):
                yield m["criteria"]
        yield from _criterios(nodo.get("children", []))


def cpes_de_bloque(bloque):
    """CPE que un bloque (CNA o ADP) declara, en cualquiera de sus dos lugares.

    `affected[].cpes` es la lista plana por producto; `cpeApplicability` es la configuracion con
    la misma estructura que usa la NVD. Cada CNA usa uno, el otro o ambos.
    """
    cpes = [c for a in bloque.get("affected", []) for c in a.get("cpes", [])]
    for configuracion in bloque.get("cpeApplicability", []):
        cpes.extend(_criterios(configuracion.get("nodes", [])))
    return cpes


def ruta_registro(cve_id):
    _, anio, num = cve_id.split("-")
    return CORPUS / anio / f"{int(num) // 1000}xxx" / f"{cve_id}.json"


def pares_persistidos():
    """Pares (cve_id, activo_id) que el artefacto dejo en la base, con su fuente."""
    sql = "select cve_id, activo_id, fuente_correlacion from telemetria_vulnerabilidades"
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d secops_research_db -At -F "," -c "{sql}"']
    salida = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout
    return {(c, int(a)): f for c, a, f in (l.split(",") for l in salida.strip().splitlines())}


def main():
    inventario = list(csv.DictReader(open(INVENTARIO, encoding="utf-8")))
    activos = {int(a["activo_id"]): (a["hostname"], claves_cpe(a["cpe"])) for a in inventario}
    ingeridos = sorted({f["cve_id"] for f in csv.DictReader(open(INGERIDOS, encoding="utf-8"))})
    persistidos = pares_persistidos()

    no_medidas, pares_cna = [], []
    cuenta = Counter()
    adp_proveedores = Counter()
    vulns_cna, vulns_cisa_con_cpe = set(), set()

    for cve_id in ingeridos:
        ruta = ruta_registro(cve_id)
        if not ruta.exists():
            no_medidas.append(cve_id)
            continue
        reg = json.loads(ruta.read_text(encoding="utf-8"))
        cuenta["medidas"] += 1
        estado = reg["cveMetadata"]["state"]
        cuenta[f"estado_{estado}"] += 1
        cont = reg.get("containers", {})

        cpes_cna = cpes_de_bloque(cont.get("cna", {}))
        if cpes_cna:
            cuenta["con_cpe_cna"] += 1
            vulns_cna.add(cve_id)
        claves_registro = set()
        for c in cpes_cna:
            k = claves_cpe(c)
            if k:
                claves_registro.update(k)
        for activo_id, (host, claves_activo) in activos.items():
            if claves_activo and any(k in claves_registro for k in claves_activo):
                pares_cna.append((cve_id, activo_id, host))

        for adp in cont.get("adp", []):
            nombre = adp.get("providerMetadata", {}).get("shortName", "?")
            adp_proveedores[nombre] += 1
            if cpes_de_bloque(adp):
                cuenta[f"adp_con_cpe_{nombre}"] += 1
                vulns_cisa_con_cpe.add(cve_id)

    vulns_correlacionadas = {c for c, _, _ in pares_cna}
    vulns_persistidas = {c for c, _ in persistidos}
    pares_nuevos = [(c, a) for c, a, _ in pares_cna if (c, a) not in persistidos]
    por_activo = Counter(h for _, _, h in pares_cna)

    SALIDA.mkdir(parents=True, exist_ok=True)
    with open(SALIDA / "pares_via_cna.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cve_id", "activo_id", "hostname", "persistido_por_el_artefacto", "fuente_en_el_artefacto"])
        for c, a, h in pares_cna:
            w.writerow([c, a, h, int((c, a) in persistidos), persistidos.get((c, a), "")])
    with open(SALIDA / "no_medidas.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["cve_id"])
        w.writerows([[c] for c in no_medidas])

    filas = [
        ("vulnerabilidades ingeridas por el flujo", "vulnerabilidades distintas", len(ingeridos)),
        ("  presentes en el corpus descargado", "vulnerabilidades distintas", cuenta["medidas"]),
        ("  no medidas (fuera del corpus, identificador anterior a 2026)", "vulnerabilidades distintas", len(no_medidas)),
        ("registros medidos en estado PUBLISHED", "vulnerabilidades distintas", cuenta["estado_PUBLISHED"]),
        ("registros medidos en estado REJECTED", "vulnerabilidades distintas", cuenta["estado_REJECTED"]),
        ("registros donde la CNA declara al menos un CPE", "vulnerabilidades distintas", cuenta["con_cpe_cna"]),
        ("via CNA: vulnerabilidades que correlacionan con algun activo", "vulnerabilidades distintas", len(vulns_correlacionadas)),
        ("via CNA: pares vulnerabilidad-activo", "pares", len(pares_cna)),
        ("via CNA: pares que el artefacto tambien persistio", "pares", len(pares_cna) - len(pares_nuevos)),
        ("via CNA: pares que el artefacto no persistio", "pares", len(pares_nuevos)),
        ("pares persistidos por el artefacto (referencia)", "pares", len(persistidos)),
        ("vulnerabilidades persistidas por el artefacto (referencia)", "vulnerabilidades distintas", len(vulns_persistidas)),
        ("via CISA: bloques de CISA-ADP presentes", "bloques de CISA", adp_proveedores["CISA-ADP"]),
        ("via CISA: bloques de CISA-ADP con productos afectados o CPE", "bloques de CISA", cuenta["adp_con_cpe_CISA-ADP"]),
        ("otros publicadores autorizados (ADP) con CPE, no CISA", "bloques de otros ADP",
         sum(v for k, v in cuenta.items() if k.startswith("adp_con_cpe_") and k != "adp_con_cpe_CISA-ADP")),
    ]
    with open(SALIDA / "resumen_vias.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["medida", "unidad", "valor"])
        w.writerows(filas)

    for m, u, v in filas:
        print(f"{v:>7}  {m}  [{u}]")
    print("\nproveedores ADP vistos:", dict(adp_proveedores))
    print("pares via CNA por activo:", dict(por_activo.most_common()))


if __name__ == "__main__":
    main()
