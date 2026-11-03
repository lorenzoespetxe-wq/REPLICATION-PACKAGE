"""Bloque 6 -- Prerevision de los 65 casos sorteados de la via de inferencia.

Para cada caso lee el registro CVE tal como lo publico la CNA (corpus local cvelistV5 de cierre)
y arma una propuesta de veredicto que el autor confirma o corrige caso por caso:
  - producto_afectado_segun_aviso: si el producto del inventario figura en la lista de
    productos afectados del registro.
  - version_en_rango: si la version del inventario cae en los rangos declarados; "no verificable"
    cuando el inventario no registra version (Windows: identificador sin numero de actualizacion).
  - coincidencia_nombres: "completa" si el texto que leyo el artefacto es el mismo producto del
    inventario; "parcial" si solo lo contiene (contencion de cadenas).
Los casos fuera de Microsoft y Apple se juzgan a mano con la lectura del registro; el motivo
queda escrito en JUICIO_MANUAL.

Criterios fijados el 04/10 tras contrastar con la revision independiente
(quality_reports/reviews/2026-10-04_bloque6_revision_independiente_inferencia.md):
  - Rango leido junto con la descripcion: una version sin soporte que el fabricante no evalua
    cuenta como afectada si la falla existe desde antes (I08 Confluence, I63 Node.js).
  - Version ausente en el inventario (Windows `-`): afectado salvo que este parcheado.
  - Condicion del entorno que el inventario no registra -- sistema operativo (OpenVPN solo
    sobre Windows) o configuracion (Proxy-Protocol de Exim) --: no se evalua; el par se juzga
    por producto y version.
    Cambio del 11/10 (decision del autor, bloque 11): I64 e I65 (OpenVPN) pasan de error de
    plataforma a correctos. La falla exige Windows y el inventario no registra el sistema de
    srv-vpn-gw: es la misma situacion que Exim, juzgado correcto. El criterio evalua producto
    y version, no exposicion. Se aparta de la recomendacion de la revision independiente del
    04/10; ver quality_reports/reviews/2026-10-04_bloque6_respuesta_a_la_revision.md.
    No equivale al error de plataforma de la via formal, donde el producto del activo no es el
    afectado sino el sistema sobre el que corre otro programa.

Entradas: data/cleaned/bloque5_muestra_validacion/planilla_revision.csv,
          data/raw/cvelistv5_cierre/cves/, data/raw/activos_inventario.csv
Salida:   data/cleaned/bloque6_revision_inferencia/propuesta.csv (sin titulos ni notas)
"""
import csv
import json
import re
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
CORPUS = RAIZ / "data" / "raw" / "cvelistv5_cierre" / "cves"
PLANILLA = RAIZ / "data" / "cleaned" / "bloque5_muestra_validacion" / "planilla_revision.csv"
INVENTARIO = RAIZ / "data" / "raw" / "activos_inventario.csv"
SALIDA = RAIZ / "data" / "cleaned" / "bloque6_revision_inferencia"

NOMBRE_EN_AVISO = {"windows_server_2016": "Windows Server 2016", "windows_server_2019": "Windows Server 2019",
                   "windows_server_2022": "Windows Server 2022", "macos": "macOS"}

# (producto_afectado, version_en_rango, par_correcto_propuesto, tipo_error, motivo)
JUICIO_MANUAL = {
    "CVE-2026-21586": ("si", "si (version sin soporte)", "si", "",
                       "Atlassian solo lista versiones con soporte; 8.2.0 no figura, pero la descripcion "
                       "dice que la falla se introdujo en 7.4.0 y 8.2 no recibio correccion"),
    "CVE-2026-21588": ("si", "no", "no", "ceguera de version",
                       "la falla se introdujo en 8.9.0; 8.2.0 es anterior"),
    "CVE-2026-56143": ("si", "si", "si", "", "8.8.0 dentro de 8.0.0 a 8.19.19"),
    "CVE-2026-78607": ("si", "si", "si", "", "8.8.0 dentro de 8.0.0 a 8.19.18"),
    "CVE-2026-94056": ("si", "si", "si", "",
                       "4.95 dentro de 4.83 a 4.100.1; explotable solo con Proxy-Protocol, configuracion no registrada"),
    "CVE-2026-94057": ("si", "si", "si", "", "4.95 anterior a 4.100.1"),
    "CVE-2026-13210": ("si", "si", "si", "", "16.0.0 dentro de 15.7 a 19.1.8"),
    "CVE-2026-3855": ("si", "no", "no", "ceguera de version", "afecta desde 18.2.7; 16.0.0 es anterior"),
    "CVE-2026-86341": ("si", "no", "no", "ceguera de version", "afecta desde 17.1, y solo a GitLab EE; 16.0.0 es anterior"),
    "CVE-2026-84656": ("si", "si", "si", "", "afecta Jenkins 2.579 y anteriores; 2.401 lo es"),
    "CVE-2026-84660": ("no", "", "no", "complemento",
                       "afecta al complemento Pipeline: Build Step, que el inventario no registra"),
    "CVE-2026-84662": ("no", "", "no", "complemento", "afecta al complemento LDAP, que el inventario no registra"),
    "CVE-2026-48932": ("si", "si (version sin soporte)", "si", "",
                       "el registro nombra solo las ramas con soporte (22, 24, 26); la 18 no se evalua y la "
                       "politica de Node.js trata como afectadas las ramas sin soporte"),
    "CVE-2026-81830": ("si", "si", "si", "",
                       "2.5.4 dentro de 2.4.0 a 2.6.22; explotable solo sobre Windows, sistema del servidor "
                       "no registrado"),
    "CVE-2026-84256": ("si", "si", "si", "",
                       "2.5.4 dentro de 2.1_rc10 a 2.6.22; explotable solo sobre Windows, sistema del servidor "
                       "no registrado"),
}


def normalizar(t):
    return re.sub(r"[^a-z0-9]", "", str(t or "").lower())


def registro(cve):
    _, anio, num = cve.split("-")
    return json.loads((CORPUS / anio / (num[:-3] + "xxx") / f"{cve}.json").read_text(encoding="utf-8"))


def url_aviso(cve, j):
    if j["cveMetadata"].get("assignerShortName") == "microsoft":
        return f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
    refs = j["containers"]["cna"].get("references", [])
    return refs[0]["url"] if refs else ""


def main():
    SALIDA.mkdir(parents=True, exist_ok=True)
    version_inv = {a["hostname"]: a["cpe"].split(":")[5] for a in csv.DictReader(INVENTARIO.open(encoding="utf-8"))}
    filas = []
    for r in csv.DictReader(PLANILLA.open(encoding="utf-8")):
        if r["via"] != "inferencia":
            continue
        cve, prod = r["cve_id"], r["producto_inventario"].split(":")[1]
        j = registro(cve)
        afectados = [a.get("product", "") for a in j["containers"]["cna"].get("affected", [])]
        leido = [p for p in afectados if normalizar(prod) in normalizar(p) or normalizar(p) in normalizar(prod)]
        coincidencia = "completa" if any(normalizar(p) == normalizar(prod) for p in leido) else "parcial"
        if cve in JUICIO_MANUAL:
            pa, vr, ok, tipo, motivo = JUICIO_MANUAL[cve]
        else:
            nombre = NOMBRE_EN_AVISO[prod]
            pa = "si" if nombre in afectados else "no"
            vr = "no verificable" if version_inv[r["activos"].split()[0]] == "-" else "si"
            ok, tipo = ("si", "") if pa == "si" else ("no", "producto")
            motivo = (f"{nombre} figura en la lista de productos afectados del registro"
                      + ("; el inventario no registra el numero de actualizacion" if vr == "no verificable"
                         else "; los rangos del registro comienzan en 0 e incluyen la version 13.0"))
        filas.append({"id": r["id"], "cve_id": cve, "producto_inventario": r["producto_inventario"],
                      "activos": r["activos"], "pares": r["pares"],
                      "cna": j["cveMetadata"].get("assignerShortName", ""), "aviso_url": url_aviso(cve, j),
                      "producto_afectado_segun_aviso": pa, "version_en_rango": vr,
                      "coincidencia_nombres": coincidencia, "texto_que_coincidio": " | ".join(leido),
                      "par_correcto_propuesto": ok, "tipo_error_propuesto": tipo, "motivo": motivo})
    with (SALIDA / "propuesta.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(filas[0].keys()))
        w.writeheader()
        w.writerows(filas)
    from collections import Counter
    print(Counter(f["par_correcto_propuesto"] for f in filas))
    print(Counter((f["tipo_error_propuesto"], f["coincidencia_nombres"]) for f in filas))


if __name__ == "__main__":
    main()
