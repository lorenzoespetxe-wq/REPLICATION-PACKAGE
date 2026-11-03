"""Bloque 1 -- Estado de cada vulnerabilidad en el momento en que el flujo la ingirio.

Lee, del historial de ejecuciones del orquestador (base interna de n8n, solo lectura), lo que
devolvio el nodo `Fetch CVEs` en cada corrida de la campana, y guarda por cada vulnerabilidad
ingerida si traia configuraciones en ese momento y cuales. Es el complemento de la reconsulta:
ambas miran el mismo conjunto de vulnerabilidades en dos instantes distintos.

El identificador de la ejecucion sale de la fila de auditoria de cada corrida (`entidad_id`).
Las credenciales no se leen ni se escriben: se usan las del propio contenedor de la base.

Salida: data/raw/estado_al_ingerir.csv
"""
import csv
import json
import subprocess
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
ENTRADA = RAIZ / "data" / "raw" / "corridas_campana.csv"
SALIDA = RAIZ / "data" / "raw" / "estado_al_ingerir.csv"
CONTENEDOR = "postgres_db"


def psql(base, sql):
    """Ejecuta una consulta de solo lectura dentro del contenedor y devuelve el texto."""
    cmd = ["docker", "exec", CONTENEDOR, "sh", "-c",
           f'psql -U "$POSTGRES_USER" -d {base} -At -c "{sql}"']
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", check=True).stdout


def decodificar(texto):
    """Decodifica el formato 'flatted' con que n8n serializa una ejecucion.

    Es una lista JSON donde los objetos y listas guardan sus valores de tipo texto como
    indices (en texto) hacia otras posiciones de la misma lista; numeros, booleanos y nulos
    van en linea.
    """
    tabla = json.loads(texto)
    memo = {}

    def resolver(i):
        if i in memo:
            return memo[i]
        valor = tabla[i]
        if isinstance(valor, dict):
            memo[i] = salida = {}
            for k, v in valor.items():
                salida[k] = resolver(int(v)) if isinstance(v, str) else v
        elif isinstance(valor, list):
            memo[i] = salida = []
            for v in valor:
                salida.append(resolver(int(v)) if isinstance(v, str) else v)
        else:
            memo[i] = salida = valor
        return salida

    return resolver(0)


def vulnerabilidades(ejecucion):
    """Todas las vulnerabilidades que devolvio `Fetch CVEs` en una ejecucion (todas las paginas)."""
    corridas_nodo = ejecucion["resultData"]["runData"]["Fetch CVEs"]
    paginas = [item["json"] for c in corridas_nodo for item in c["data"]["main"][0]]
    return [v for p in paginas for v in p.get("vulnerabilities", [])]


def main():
    with ENTRADA.open(encoding="utf-8", newline="") as f:
        corridas = list(csv.DictReader(f))
    filas, resumen = [], []
    for r in corridas:
        fila = r["fila_auditoria"]
        ejec = psql("secops_research_db",
                    f"SELECT entidad_id FROM auditoria_acciones WHERE id={fila};").strip()
        texto = psql("n8n_internal",
                     f'SELECT data FROM execution_data WHERE \\"executionId\\"={ejec};').strip()
        vulns = vulnerabilidades(decodificar(texto))
        for v in vulns:
            cve = v["cve"]
            configs = cve.get("configurations", [])
            cpes = [m["criteria"] for c in configs for n in c.get("nodes", [])
                    for m in n.get("cpeMatch", []) if m.get("criteria")]
            filas.append({"fila_auditoria": fila, "ts_utc": r["ts_utc"], "cve_id": cve["id"],
                          "n_configs": len(configs), "cpes": " ".join(cpes)})
        resumen.append((fila, ejec, len(vulns), r["cve_ingeridos"]))
        print(f"fila {fila} ejecucion {ejec}: {len(vulns)} vulnerabilidades (auditoria: {r['cve_ingeridos']})", flush=True)

    with SALIDA.open("w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["fila_auditoria", "ts_utc", "cve_id", "n_configs", "cpes"])
        w.writeheader()
        w.writerows(filas)
    difieren = [x for x in resumen if int(x[2]) != int(x[3])]
    print(f"\nFilas guardadas: {len(filas)} | corridas cuyo conteo difiere de la auditoria: {len(difieren)}")
    for x in difieren:
        print("  difiere:", x)


if __name__ == "__main__":
    main()
