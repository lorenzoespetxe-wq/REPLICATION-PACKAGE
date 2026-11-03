# Paquete de reproducibilidad

Artefactos necesarios para reconstruir el entorno de la Prueba de Concepto descrita en
la tesis.

## Contenido

- `docker-compose.yml`: levanta PostgreSQL 16, n8n 2.26.8 y pgAdmin 9.16 en una red
  aislada.
- `init-db.sh` e `init-db.sql`: crean la base de investigación `secops_research_db`,
  su esquema y el inventario simulado de 30 activos. Deben permanecer en la misma
  carpeta que `docker-compose.yml`, que los monta por ruta relativa.
- `.env.example`: variables que requiere `docker-compose.yml`, sin valores reales.
- `database/esquema_secops_research_db.sql`: volcado del esquema de la base en operación
  (`pg_dump --schema-only`, 19/10/2026), sin datos. Coincide con `init-db.sql` en sus cinco
  tablas y cincuenta y cuatro columnas; sirve para comprobarlo, no para levantar el entorno.
- `database/secops_research_db_campana.sql`: volcado completo de la base de investigación,
  con datos (`pg_dump --no-owner --no-privileges`, 20/10/2026). Contiene las 3.883 filas de
  telemetría de la campaña, el inventario, la auditoría y la serie diaria de la probabilidad de
  explotación. No contiene direcciones de correo ni credenciales. Se restauró en una base de
  prueba con los mismos conteos por tabla.
- `analisis/`: scripts y datos que producen las cifras de la tesis (ver más abajo).
- `n8n_workflows/`: flujos exportados desde n8n.
  - `Refactored Workflow 1.3(After Patch Tuesday).json`: flujo de campaña.
  - `Workflow de Reevaluación Diferida 1.1.json`: flujo de reevaluación diferida.
  - `Webhook Workflow.json`: circuito de reprocesamiento bajo demanda en la versión
    que invoca la interfaz, modificada el 25/10/2026: registra cada reproceso en
    `auditoria_acciones` (`N8N_REPROCESO`) en lugar de reescribir el estado, la fecha
    de alerta y el `message_id` del par. La versión de la recolección sigue dentro
    del flujo de campaña, así que **no importar ambos** en la misma instancia: se
    duplicaría el circuito. Para reproducir la campaña alcanzan los dos primeros.

## Cómo levantar el entorno

1. Copiar `.env.example` como `.env` y completar los valores.
2. Ejecutar `docker compose up -d` desde esta carpeta.
3. Abrir n8n en `http://localhost:5678` e importar el flujo de campaña y el de
   reevaluación diferida desde `n8n_workflows/`.
4. Crear en n8n las tres credenciales que los flujos referencian por nombre:
   - `Postgres account`: base `secops_research_db`, host `db`, puerto `5432`.
   - `Gmail account`: credencial OAuth2 de Gmail.
   - `Header Auth account`: encabezado `apiKey` con una clave de la API 2.0 de la NVD.
5. En los nodos `Send Alert` y `Send Alert.` del flujo de campaña, reemplazar el
   destinatario de las alertas.

## Diferencias con el entorno de la campaña

- El destinatario de las alertas se reemplazó por `analista@ejemplo.org`. Es el único
  cambio respecto de los flujos ejecutados durante la campaña.
- El circuito bajo demanda se separó a un lienzo propio después del cierre de la
  recolección. No se invocó en ninguna oportunidad durante la campaña, de modo que
  la separación no altera ningún dato.
- Los valores del archivo `.env` y de las credenciales de n8n no se publican.
- Los comentarios del esquema, en `init-db.sql` y en el volcado, corresponden a una versión
  anterior de la tesis: remiten a otra numeración de secciones y mencionan la medición del
  tiempo medio de detección. El archivo incorpora los cambios posteriores a la primera
  inicialización (la corrección de identificadores de agosto de 2026 y las estructuras del
  1 de septiembre), de modo que refleja el esquema final y no el inicial.

## Reanálisis de las cifras

La carpeta `analisis/` reproduce la estructura del repositorio de trabajo, de modo que los
scripts corren sin cambios desde ella (`python scripts/<script>.py`):

- `scripts/`: un script por bloque de trabajo. Cada uno declara en su encabezado qué cifra
  produce, qué lee y qué escribe.
- `data/raw/`: descargas de la NVD y de FIRST, y extracciones de la base usadas por los scripts.
  La descarga de la verificación de versiones va comprimida (`nvd_verificacion_version.zip`);
  hay que descomprimirla en el mismo lugar.
- `data/cleaned/`, `paper/tables/`: salidas de los scripts, tal como las usa la tesis.
- `quality_reports/reviews/`: los registros de revisión de la vía de inferencia y de la vía
  formal, la reclasificación del 11 de octubre y la revisión a ciegas de
  `2026-10-21_revision_3/muestra_sonnet/`. El registro del sorteo está en
  `data/cleaned/bloque5_muestra_validacion/registro_sorteo.json`.

Dos condiciones:

1. Los scripts que consultan la base lo hacen con `docker exec` sobre el contenedor
   `postgres_db`. Antes hay que levantar el entorno y restaurar el volcado. Como el primer
   arranque ya crea la base y carga el inventario, se la recrea vacía y se restaura encima:
   `docker exec postgres_db sh -c 'dropdb -U "$POSTGRES_USER" secops_research_db && createdb -U "$POSTGRES_USER" secops_research_db'`
   y luego
   `docker exec -i postgres_db sh -c 'psql -U "$POSTGRES_USER" -d secops_research_db' < database/secops_research_db_campana.sql`.
2. Los scripts que leen el registro de la CNA (`bloque2_via_cna_cisa.py`,
   `bloque6_prerevision_inferencia.py`, `bloque7_prerevision_formal.py`,
   `bloque11_notificaciones.py`, `bloque12_origen_severidad.py`,
   `bloque28b_piso_rangos_windows.py`) necesitan el corpus público
   `cvelistV5` en la etiqueta `cve_2026-09-27_at_end_of_day`, descargado en
   `data/raw/cvelistv5_cierre/` (https://github.com/CVEProject/cvelistV5). No se incluye por
   tamaño.

Los scripts que consultan la API de la NVD leen la clave de la variable de entorno
`NVD_API_KEY`. Sus respuestas cambian con el tiempo, de modo que repetir esas descargas no
reproduce los archivos de `data/raw/`: los archivos incluidos son los de la campaña.

## Agregado tras la devolución del tribunal (noviembre de 2026)

`analisis/scripts/devolucion_*.py` y sus salidas en `analisis/data/cleaned/devolucion_*`: qué devolvió la consulta del diseño original en agosto, qué habría detectado durante la campaña, la demora de la NVD con observaciones censuradas y los nombres de Windows Server. El primero lee el respaldo de la base interna de n8n, que no viaja en el paquete; su salida sí está. El segundo necesita descomprimir `nvd_verificacion_version.zip`. `analisis/quality_reports/reviews/` reúne los registros de revisión de ambas vías y la reclasificación del 11/10.
