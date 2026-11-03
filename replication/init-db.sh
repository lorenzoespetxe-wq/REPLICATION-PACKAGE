#!/bin/bash
# =============================================================================
# init-db.sh
# Script de inicialización del entorno de base de datos para la PoC de tesis.
#
# FUNDAMENTO DEL CAMBIO (Observación #1 de la revisión):
# El mecanismo docker-entrypoint-initdb.d ejecuta los scripts .sql conectado
# a la base de datos definida en POSTGRES_DB (n8n_internal), dentro de un
# contexto que no permite la ejecución de CREATE DATABASE mediante SQL puro,
# ya que PostgreSQL no admite esta sentencia dentro de bloques de transacción
# implícita (error: "CREATE DATABASE cannot run inside a transaction block").
#
# La solución adoptada divide la responsabilidad en dos archivos:
#   - init-db.sh  → crea la base de datos de investigación usando psql con
#                   el flag --no-transaction (-1 no aplica para CREATE DB),
#                   invocado directamente como superusuario.
#   - init-db.sql → contiene exclusivamente el DDL (tablas, índices) y los
#                   datos del inventario simulado, ejecutado sobre la DB
#                   recién creada por este script.
#
# Referencia: PostgreSQL Documentation §23.2 — Creating a Database.
# Docker entrypoint docs: https://hub.docker.com/_/postgres (sección initdb).
# =============================================================================

set -e  # Abortar ante cualquier error no manejado

# Variables heredadas del entorno del contenedor (definidas en docker-compose.yml)
DB_RESEARCH="secops_research_db"
DB_USER="${POSTGRES_USER}"

echo ">>> [init-db.sh] Iniciando creación de base de datos de investigación: ${DB_RESEARCH}"

# Crear la base de datos de investigación solo si no existe.
# Se usa psql con ON_ERROR_STOP=1 para detectar fallos explícitos.
psql -v ON_ERROR_STOP=1 --username "${DB_USER}" --dbname "postgres" <<-EOSQL
    SELECT 'CREATE DATABASE ${DB_RESEARCH}'
    WHERE NOT EXISTS (
        SELECT FROM pg_database WHERE datname = '${DB_RESEARCH}'
    )\gexec
EOSQL

echo ">>> [init-db.sh] Base de datos '${DB_RESEARCH}' verificada/creada."
echo ">>> [init-db.sh] Ejecutando DDL e inserción de inventario desde init-db.sql..."

# Ejecutar el script SQL sobre la base de datos de investigación recién creada
psql -v ON_ERROR_STOP=1 --username "${DB_USER}" --dbname "${DB_RESEARCH}" \
     -f /opt/seed/init-db.sql

echo ">>> [init-db.sh] Inicialización completada exitosamente."
