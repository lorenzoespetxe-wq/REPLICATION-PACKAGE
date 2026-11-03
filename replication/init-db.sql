-- =============================================================================
-- init-db.sql
-- Esquema relacional y población del inventario simulado
-- Tesis: "Notificación Automatizada de Vulnerabilidades mediante CVE y n8n"
-- Autor: Lorenzo Espetxe — UTN Facultad Regional Mendoza — 2026
--
-- NOTA DE EJECUCIÓN:
-- Este script NO debe contener CREATE DATABASE ni \c.
-- Es invocado por init-db.sh sobre la base de datos 'secops_research_db'
-- ya creada. Ver fundamento en init-db.sh (Observación #1 de revisión).
--
-- SINCRONIZACIÓN CON EL ESQUEMA REAL (revisión de consistencia post-C-10/C-11):
-- Este script estaba desactualizado respecto del esquema efectivamente en uso
-- (verificado contra backup de estructura). Se incorporan tres correcciones:
--   1. Tabla auditoria_acciones completa (faltaba por completo).
--   2. Columnas fecha_hitl_update y fecha_actualizacion_datos en
--      telemetria_vulnerabilidades (faltaban).
--   3. CHECK de telemetria_vulnerabilidades.estado ampliado con los tres
--      estados HITL: EN_REVISION, REMEDIADA, DESCARTADA.
--
-- AMPLIACION DEL 01/09/2026 (Fase 5 - reevaluacion diferida):
-- Se agrega al final del script el PASO 5.1, con la tabla epss_serie_diaria y
-- seis columnas nuevas en telemetria_vulnerabilidades. Fundamento: apartados
-- 15.8 y 16 de la Propuesta de Refactorizacion.
-- =============================================================================


-- =============================================================================
-- PASO 1.2 — MODELADO DE BASE DE DATOS
-- =============================================================================


-- -----------------------------------------------------------------------------
-- TABLA: criticidad_niveles
-- Tabla de referencia (lookup) para la escala ordinal de criticidad.
-- Centraliza el significado de cada nivel, elimina CASE WHEN en las queries
-- analíticas del Capítulo 5 y hace el esquema autodescriptivo.
-- La columna peso_normalizacion almacena directamente CRITnorm = id / 4,
-- el factor usado en el cálculo del IRC (sección 3.6), evitando la
-- división en cada ejecución del pipeline de n8n.
-- -----------------------------------------------------------------------------

CREATE TABLE criticidad_niveles (
    id                   INTEGER PRIMARY KEY,   -- 1=Baja, 2=Media, 3=Alta, 4=Crítica
    nombre               VARCHAR(20) NOT NULL UNIQUE,
    descripcion          TEXT,
    -- CRITnorm = id / 4.0 (precalculado para el IRC, sección 3.6)
    peso_normalizacion   NUMERIC(5, 4) GENERATED ALWAYS AS (id / 4.0) STORED
);

COMMENT ON TABLE criticidad_niveles IS
    'Tabla de referencia para la escala ordinal de criticidad organizacional. '
    'Sección 3.5 de la tesis. La columna peso_normalizacion provee CRITnorm = id/4 '
    'listo para el cálculo del IRC en el pipeline n8n.';

INSERT INTO criticidad_niveles (id, nombre, descripcion) VALUES
(1, 'Baja',    'Activos de soporte o entornos no productivos. Impacto mínimo en la continuidad del negocio.'),
(2, 'Media',   'Activos de servicio general. Impacto moderado ante una brecha de seguridad.'),
(3, 'Alta',    'Activos de infraestructura crítica de soporte. Impacto significativo ante compromiso.'),
(4, 'Crítica', 'Crown Jewels: sistemas esenciales para la continuidad operativa. Máxima prioridad de remediación.');


-- -----------------------------------------------------------------------------
-- TABLA: activos
-- Almacena el inventario simulado de 30 activos tecnológicos.
-- Cada activo posee las dos variables de contexto interno definidas en la
-- sección 3.5 de la tesis: criticidad organizacional y exposición a Internet.
-- -----------------------------------------------------------------------------

CREATE TABLE activos (
    id                  SERIAL PRIMARY KEY,
    hostname            VARCHAR(100) NOT NULL,

    -- Alias descriptivo del activo para visualización en frontend.
    -- Nombre legible por humanos que describe la función del activo.
    alias               VARCHAR(200),

    -- Identificador CPE 2.3 (Common Platform Enumeration).
    -- Es el vector de correlación entre el inventario interno y los registros
    -- de la NVD. Debe respetar estrictamente los 13 componentes del estándar
    -- WFN (Well-Formed Name) definido por NIST:
    -- cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:
    --         <language>:<sw_edition>:<target_sw>:<target_hw>:<other>
    -- Referencia: NIST IR 7695 — CPE Naming Specification Version 2.3.
    cpe                 VARCHAR(255) NOT NULL,

    -- FK a criticidad_niveles. Garantiza integridad referencial y permite
    -- JOIN directo en las queries analíticas del Capítulo 5, evitando CASE WHEN.
    -- Escala: 1=Baja | 2=Media | 3=Alta | 4=Crítica (sección 3.5).
    -- CRITnorm = criticidad_id / 4 para el IRC (sección 3.6).
    criticidad_id       INTEGER NOT NULL REFERENCES criticidad_niveles(id),

    -- Variable dicotómica de exposición a Internet (sección 3.5).
    -- TRUE  → activo publicado en DMZ / accesible desde exterior (EXP = 1 en IRC).
    -- FALSE → activo en red interna segmentada (EXP = 0 en IRC).
    exposicion_internet BOOLEAN NOT NULL,

    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

COMMENT ON TABLE activos IS
    'Inventario simulado de 30 activos tecnológicos. Representa la CMDB de la '
    'organización en el entorno controlado de la PoC. Sección 3.4 de la tesis.';

COMMENT ON COLUMN activos.criticidad_id IS
    'FK a criticidad_niveles. Nivel ordinal: 1=Baja, 2=Media, 3=Alta, 4=Crítica. '
    'Distribución: 9-12-6-3 activos respectivamente (sección 3.4). '
    'Usar JOIN criticidad_niveles en queries analíticas del Capítulo 5.';

COMMENT ON COLUMN activos.cpe IS
    'Identificador CPE 2.3 con 13 componentes exactos según NIST IR 7695. '
    'Vector de correlación con la API v2.0 de la NVD en Fase 2.';

COMMENT ON COLUMN activos.exposicion_internet IS
    'TRUE = accesible desde Internet (DMZ). FALSE = red interna. '
    'Distribución: 6 TRUE / 24 FALSE (20%/80%, sección 3.4).';

COMMENT ON COLUMN activos.alias IS
    'Alias descriptivo del activo para visualización en frontend. '
    'Nombre legible que reemplaza al hostname técnico en la UI.';

-- Índice sobre CPE: columna de búsqueda principal durante la correlación
-- que realiza n8n en Fase 2 (string matching entre respuesta NVD e inventario).
CREATE INDEX idx_activos_cpe ON activos(cpe);


-- -----------------------------------------------------------------------------
-- TABLA: telemetria_vulnerabilidades
-- Registro histórico de cada evento de vulnerabilidad procesado por el pipeline.
-- Es el repositorio de datos empíricos para el benchmarking del MTTD (sección 3.7).
--
-- DISEÑO DE TIMESTAMPS (Observación #2 de revisión):
-- La tesis requiere medir el MTTD como la latencia entre la publicación de la
-- vulnerabilidad en NVD y la generación de la alerta (sección 3.7 y 3.11).
-- El esquema original usaba DEFAULT CURRENT_TIMESTAMP para fecha_deteccion_sistema,
-- lo que captura el momento del INSERT —no el momento real de detección por el
-- pipeline—, introduciendo un sesgo temporal sistemático en la métrica.
--
-- Se adoptan tres timestamps explícitos de responsabilidad separada:
--   1. fecha_publicacion_nvd   → provisto por la API de NVD (dato externo).
--   2. fecha_ingesta_pipeline  → registrado por n8n al iniciar el procesamiento.
--   3. fecha_alerta_generada   → registrado por n8n al emitir la notificación.
--
-- -----------------------------------------------------------------------------

CREATE TABLE telemetria_vulnerabilidades (
    id                      SERIAL PRIMARY KEY,

    cve_id                  VARCHAR(20) NOT NULL,
    activo_id               INTEGER NOT NULL REFERENCES activos(id),

    -- Variables externas capturadas desde NVD y First.org (sección 3.5)
    cvss_score              NUMERIC(4, 2)  CHECK (cvss_score BETWEEN 0 AND 10),
    epss_score              NUMERIC(5, 4)  CHECK (epss_score BETWEEN 0 AND 1),
    kev_status              BOOLEAN,

    -- Resultado del modelo de priorización (sección 3.6)
    irc_score               NUMERIC(5, 4)  CHECK (irc_score BETWEEN 0 AND 1),
    prioridad               VARCHAR(20)    CHECK (prioridad IN ('CRITICA', 'ALTA', 'INFORMATIVA')),

    -- -------------------------------------------------------------------------
    -- TIMESTAMPS DE TRAZABILIDAD (Observación #2 — granularidad de etapas)
    -- Tres marcas temporales inmutables que documentan el ciclo de vida completo
    -- de cada evento, habilitando la auditoría exigida en la sección 2.8.
    -- -------------------------------------------------------------------------

    -- T1: Fecha de publicación oficial en NVD. Extraído del campo
    -- 'published' de la respuesta JSON de la API v2.0 de la NVD.
    -- NOT NULL porque es el origen del intervalo de MTTD.
    fecha_publicacion_nvd   TIMESTAMP NOT NULL,

    -- T2: Momento en que el nodo de n8n inició el procesamiento de este CVE.
    -- Registrado explícitamente por el orquestador al comenzar el ciclo,
    -- no como DEFAULT, para reflejar la latencia real de ingesta.
    fecha_ingesta_pipeline  TIMESTAMP,

    -- T3: Momento exacto en que se persistió la alerta priorizada.
    -- Para registros INFORMATIVOS (IRC < 0.40) que no generan email,
    -- este timestamp marca igualmente el cierre del procesamiento.
    fecha_alerta_generada   TIMESTAMP,

    -- Identificador del mensaje de notificación enviado
    message_id              VARCHAR(255),

    -- Descripción textual de la vulnerabilidad desde NVD
    cve_description         TEXT,

    -- URL al detalle de la vulnerabilidad en NVD
    nvd_url                 VARCHAR(512),

    -- URL a la página de EPSS en FIRST.org
    epss_url                VARCHAR(512),

    -- T4: Momento de la última transición HITL sobre este registro
    -- (EN_REVISION, REMEDIADA, DESCARTADA). Se actualiza cada vez que un
    -- analista interviene manualmente sobre el estado del hallazgo. C-10.
    fecha_hitl_update       TIMESTAMP,

    -- Marca de la última actualización de datos externos (CVSS/EPSS/KEV)
    -- sobre un registro ya existente, para trazar re-consultas del pipeline
    -- a NVD/FIRST.org sobre un mismo CVE-activo ya ingresado.
    fecha_actualizacion_datos TIMESTAMP,


    -- -------------------------------------------------------------------------
    -- ESTADO DEL CICLO DE VIDA (Observación #6 — campo faltante)
    -- La sección 3.9 describe un modelo de "actualización incremental donde
    -- cada registro es enriquecido progresivamente". La sección 3.11 menciona
    -- "transición de estados". Sin este campo, el esquema no puede representar
    -- en qué etapa del pipeline se encuentra cada vulnerabilidad, ni auditar
    -- el ciclo completo exigido en la sección 2.8.
    --
    -- Estados del ciclo de vida:
    --   DETECTADA    → CVE correlacionado con inventario.
    --   NOTIFICADA   → Email enviado vía nodo Gmail (IRC >= 0.40).
    --   INFORMATIVA  → Procesamiento completo, IRC < 0.40, sin notificación.
    --   EN_REVISION  → Estado HITL: un analista tomó el hallazgo para revisión. C-10.
    --   REMEDIADA    → Estado HITL: el hallazgo fue remediado por un analista. C-10.
    --   DESCARTADA   → Estado HITL: el hallazgo fue descartado (falso positivo/aceptado). C-10.
    -- -------------------------------------------------------------------------
    estado                  VARCHAR(30) NOT NULL DEFAULT 'DETECTADA'
                                CHECK (estado IN (
                                    'DETECTADA',
                                    'NOTIFICADA',
                                    'INFORMATIVA',
                                    'EN_REVISION',
                                    'REMEDIADA',
                                    'DESCARTADA'
                                )),

    -- -------------------------------------------------------------------------
    -- CORRELACIÓN FEDERADA (refactorización 2026 — propuesta R3)
    -- Tras el abandono del enriquecimiento universal de CVE por parte del NIST
    -- (15/04/2026), la correlación CVE-activo deja de ser provista por la NVD y
    -- pasa a resolverse localmente mediante una cascada de fuentes. Cada
    -- coincidencia registra qué capa la resolvió y con qué grado de certeza.
    --
    --   NVD        → CPE publicado por el NIST (campo 'configurations').
    --   CNA        → CPE publicado por el fabricante que reportó el CVE.
    --   ADP        → CPE publicado por CISA Vulnrichment (rol Authorized Data Publisher).
    --   HEURISTICA → derivación local por vendor/producto/versión en texto.
    --
    -- Las tres primeras comparan identificadores formales: coinciden o no.
    -- La cuarta infiere, y por eso puede producir falsos positivos y negativos.
    -- Sin esta distinción persistida, ningún resultado agregado sobre esta tabla
    -- puede separar coincidencias verificables de coincidencias inferidas.
    -- -------------------------------------------------------------------------
    fuente_correlacion      VARCHAR(20)
                                CHECK (fuente_correlacion IN (
                                    'NVD',
                                    'CNA',
                                    'ADP',
                                    'HEURISTICA'
                                )),

    nivel_confianza         VARCHAR(10)
                                CHECK (nivel_confianza IN (
                                    'FORMAL',
                                    'INFERIDA'
                                )),

    -- -------------------------------------------------------------------------
    -- INSTRUMENTACIÓN TEMPORAL AMPLIADA (propuesta R6)
    -- Campo 'lastModified' del registro CVE. Se usa como estimación del momento
    -- en que el dato de correlación estuvo disponible, insumo de la latencia de
    -- correlación (T2 en R6) y de la hipótesis H3.
    --
    -- LIMITACIÓN DECLARADA: 'lastModified' se actualiza ante cualquier
    -- modificación del registro, no exclusivamente ante la incorporación del
    -- dato de correlación. El intervalo derivado es una aproximación por exceso
    -- y debe reportarse como tal.
    -- -------------------------------------------------------------------------
    fecha_modificacion_nvd  TIMESTAMP,

    -- -------------------------------------------------------------------------
    -- EXPLOTACIÓN SEGÚN SSVC (propuesta R7 — solo persistencia)
    -- Valor del punto de decisión 'exploitation' publicado por CISA en el
    -- contenedor ssvcV203, disponible dentro de la propia respuesta de la API
    -- 2.0 de la NVD. Tres estados, en minúscula tal como los emite la fuente:
    --
    --   active → explotación observada en la práctica.
    --   poc    → prueba de concepto pública, sin explotación observada.
    --   none   → sin evidencia.
    --
    -- La fórmula del IRC NO utiliza este campo: mantiene kev_status booleano,
    -- que colapsa 'poc' y 'none' en un mismo valor. El campo se persiste para
    -- poder cuantificar esa pérdida de granularidad en el análisis de
    -- resultados sin comprometer la justificación de pesos de la sección 3.6.
    -- -------------------------------------------------------------------------
    ssvc_exploitation       VARCHAR(10)
                                CHECK (ssvc_exploitation IN (
                                    'none',
                                    'poc',
                                    'active'
                                )),

    -- -------------------------------------------------------------------------
    -- PROMOCIÓN DE FUENTE DE CORRELACIÓN (refactorización 2026 — sesión 28/08)
    -- Un par CVE-activo detectado por la capa heurística puede, días más tarde,
    -- resultar confirmado por una fuente formal cuando el NIST completa el
    -- enriquecimiento del registro. Medición del 27/08/2026: diez CVE recibieron
    -- dato CPE entre 22,8 y 40,3 horas después de su publicación.
    --
    -- Ese fenómeno era invisible en el diseño original: el nodo IF del flujo
    -- derivaba los pares preexistentes a una salida no conectada, de modo que
    -- ningún registro se actualizaba nunca tras su inserción.
    --
    -- DECISIÓN SEMÁNTICA: 'fuente_correlacion' conserva el significado de fuente
    -- de DETECCIÓN INICIAL y no se sobrescribe. La promoción se registra aparte.
    -- Sobrescribir el campo original habría alterado retroactivamente el
    -- significado de los datos ya recolectados y de lo que H1 mide.
    --
    -- Solo se registra la PRIMERA promoción observada: el nodo Register
    -- Promotion condiciona el UPDATE a 'fuente_correlacion_final IS NULL'.
    -- Sin esa guarda, cada corrida diaria pisaría la fecha con un lastModified
    -- más reciente y la latencia resultaría inflada.
    -- -------------------------------------------------------------------------

    -- Fuente formal que confirmó una correlación originalmente heurística.
    -- NULL mientras el par no haya sido promovido, que es el caso mayoritario.
    fuente_correlacion_final    VARCHAR(20)
                                    CHECK (fuente_correlacion_final IN (
                                        'NVD',
                                        'CNA',
                                        'ADP'
                                    )),

    -- Valor de 'lastModified' publicado por el NIST en el momento en que se
    -- observó la promoción. Insumo de la latencia de enriquecimiento.
    --
    -- LIMITACIÓN DECLARADA, MEDIDA EL 28/08/2026: el NIST estampa este campo por
    -- lotes. Ocho CVE publicados en dos fechas distintas presentaron un valor
    -- idéntico al milisegundo (2026-08-28 15:44:39.323). La resolución efectiva
    -- del dato es el lote, no el registro individual. Se suma a la limitación ya
    -- declarada en fecha_modificacion_nvd: el campo refleja la última
    -- modificación de cualquier tipo, no específicamente la incorporación de CPE.
    fecha_enriquecimiento_nvd   TIMESTAMP,

    -- Momento en que el pipeline observó la promoción. NO es la métrica: su
    -- resolución está acotada por la frecuencia de ejecución (±24 h). Se
    -- persiste como rastro de auditoría, porque las actualizaciones no generan
    -- fila en auditoria_acciones y sin este campo no sería posible reconstruir
    -- en qué corrida ocurrió cada promoción.
    fecha_promocion_detectada   TIMESTAMP,

    -- Evita reprocessar el mismo par CVE-activo en ejecuciones sucesivas del pipeline
    CONSTRAINT unique_activo_cve UNIQUE (activo_id, cve_id)
);

COMMENT ON TABLE telemetria_vulnerabilidades IS
    'Registro histórico de vulnerabilidades procesadas por el pipeline. '
    'Fuente primaria de datos empíricos para el benchmarking del MTTD. '
    'Secciones 2.8, 3.7 y 3.11 de la tesis.';

COMMENT ON COLUMN telemetria_vulnerabilidades.estado IS
    'Estado actual en el ciclo de vida del procesamiento. Incluye pipeline '
    '(DETECTADA → NOTIFICADA/INFORMATIVA) y estados HITL (EN_REVISION → '
    'REMEDIADA, DESCARTADA). C-10.';

COMMENT ON COLUMN telemetria_vulnerabilidades.fecha_hitl_update IS
    'Timestamp de la última transición HITL (EN_REVISION, REMEDIADA, '
    'DESCARTADA). C-10.';

COMMENT ON COLUMN telemetria_vulnerabilidades.fuente_correlacion_final IS
    'Fuente formal que confirmó una correlación originalmente heurística. '
    'NULL si el par nunca fue promovido. No sobrescribe fuente_correlacion, '
    'que conserva la fuente de detección inicial.';

COMMENT ON COLUMN telemetria_vulnerabilidades.fecha_enriquecimiento_nvd IS
    'lastModified del NIST al observarse la promoción. La latencia de '
    'enriquecimiento se calcula como (fecha_enriquecimiento_nvd - '
    'fecha_publicacion_nvd). Aproximación: el NIST estampa el campo por lotes.';

COMMENT ON COLUMN telemetria_vulnerabilidades.fecha_promocion_detectada IS
    'Corrida en que el pipeline observó la promoción. Rastro de auditoría, no '
    'métrica: su resolución está acotada por la frecuencia de ejecución.';

COMMENT ON COLUMN telemetria_vulnerabilidades.irc_score IS
    'Índice de Riesgo Compuesto calculado según fórmula de sección 3.6: '
    'IRC = 0.15*CVSSnorm + 0.25*EPSS + 0.30*KEV + 0.20*CRITnorm + 0.10*EXP';

-- Índices para optimizar consultas del pipeline y análisis de telemetría
CREATE INDEX idx_tv_cve_id          ON telemetria_vulnerabilidades(cve_id);
CREATE INDEX idx_tv_activo_id       ON telemetria_vulnerabilidades(activo_id);
CREATE INDEX idx_tv_estado          ON telemetria_vulnerabilidades(estado);
CREATE INDEX idx_tv_prioridad       ON telemetria_vulnerabilidades(prioridad);

-- Índice parcial sobre las filas promovidas (sesión 28/08/2026). El análisis de
-- latencia de enriquecimiento consulta exclusivamente este subconjunto, que es
-- una fracción minoritaria de la tabla.
CREATE INDEX idx_tv_promovidas      ON telemetria_vulnerabilidades(fuente_correlacion_final)
                                    WHERE fuente_correlacion_final IS NOT NULL;

-- Índice por fecha de publicación (Observación #7 — faltante en esquema original).
-- Todas las consultas analíticas del Capítulo 5 filtran por ventanas temporales.
-- Sin este índice, dichas queries realizan full scan sobre la tabla de telemetría.
CREATE INDEX idx_tv_fecha_publicacion ON telemetria_vulnerabilidades(fecha_publicacion_nvd);


-- -----------------------------------------------------------------------------
-- TABLA: auditoria_acciones
-- Log de auditoría de acciones humanas sobre el sistema: re-envíos de
-- notificaciones, cambios de estado y transiciones HITL (Human-In-The-Loop).
-- Requisito de trazabilidad de la sección 2.8 de la tesis (C-11).
--
-- La entidad afectada se referencia de forma polimórfica mediante
-- (tipo_entidad, entidad_id) en lugar de una FK directa, ya que
-- auditoria_acciones puede registrar acciones sobre distintos tipos de
-- entidad del dominio (actualmente: vulnerabilidad). Por eso entidad_id
-- no tiene REFERENCES: la integridad referencial se resuelve a nivel de
-- aplicación (n8n / backend), no de base de datos.
-- -----------------------------------------------------------------------------

-- -----------------------------------------------------------------------------
-- USO ADICIONAL TRAS LA REFACTORIZACIÓN 2026 (hipótesis H1)
-- Con el flujo delta-driven (propuesta R2), cada corrida ingiere el universo
-- completo de CVE publicados en la ventana, del cual solo una fracción
-- correlaciona con el inventario y llega a telemetria_vulnerabilidades. El
-- resto no deja rastro en esa tabla, y sin él la proporción de cobertura que
-- mide H1 carece de denominador.
--
-- Cada corrida escribe aquí una fila de cierre:
--   accion        = 'INGESTA_DELTA'
--   tipo_entidad  = 'EJECUCION'
--   entidad_id    = identificador de ejecución de n8n (entero, sin FK)
--   metadata_json = { "cve_ingeridos": N, "correlacionados": M,
--                     "n1": .., "n2": .., "n3": .., "n4": ..,
--                     "ids": ["CVE-...", ...] }
--
-- El arreglo "ids" permite verificar casos puntuales a mano, reconstruir por
-- diferencia qué CVE quedaron sin correlacionar, y reprocesar la ventana si la
-- heurística se corrige. Sin él solo se podría reportar el cociente.
-- -----------------------------------------------------------------------------

CREATE TABLE auditoria_acciones (
    id              SERIAL PRIMARY KEY,

    -- Acción ejecutada: RESEND, STATUS_CHANGE, HITL_TRANSITION.
    accion          VARCHAR(50) NOT NULL,

    -- Tipo de entidad afectada por la acción (actualmente: 'vulnerabilidad').
    tipo_entidad    VARCHAR(50) NOT NULL,

    -- Identificador de la entidad afectada. Referencia polimórfica: junto
    -- con tipo_entidad, apunta a la fila correspondiente (p. ej. el id de
    -- telemetria_vulnerabilidades cuando tipo_entidad = 'vulnerabilidad').
    entidad_id      INTEGER NOT NULL,

    -- Momento en que se ejecutó la acción.
    "timestamp"     TIMESTAMP NOT NULL DEFAULT now(),

    -- Datos contextuales de la acción en formato JSON (ej. estado anterior/
    -- nuevo, usuario que la ejecutó, motivo de descarte, etc.).
    metadata_json   JSONB
);

COMMENT ON TABLE auditoria_acciones IS
    'Log de auditoría de acciones humanas: re-envíos, cambios de estado, '
    'transiciones HITL. C-11.';

COMMENT ON COLUMN auditoria_acciones.accion IS
    'RESEND, STATUS_CHANGE, HITL_TRANSITION';

COMMENT ON COLUMN auditoria_acciones.tipo_entidad IS
    'Tipo de entidad afectada: vulnerabilidad';

COMMENT ON COLUMN auditoria_acciones.metadata_json IS
    'Datos contextuales de la acción en formato JSON (JSONB).';

-- Índices para las consultas de auditoría (filtrado por entidad, tipo,
-- acción y ventana temporal).
CREATE INDEX idx_aa_accion       ON auditoria_acciones(accion);
CREATE INDEX idx_aa_entidad_id   ON auditoria_acciones(entidad_id);
CREATE INDEX idx_aa_timestamp    ON auditoria_acciones("timestamp");
CREATE INDEX idx_aa_tipo_entidad ON auditoria_acciones(tipo_entidad);


-- =============================================================================
-- PASOS 1.3 y 1.4 — POBLACIÓN DEL INVENTARIO SIMULADO
--
-- 30 activos distribuidos según sección 3.4:
--   Criticidad : 3 Crítica (4) | 6 Alta (3) | 12 Media (2) | 9 Baja (1)
--   Exposición : 6 TRUE (20%)  | 24 FALSE (80%)
--
-- FORMATO CPE 2.3 (Observación #4 — CPEs Windows malformados):
-- El estándar NIST IR 7695 define 13 componentes en toda cadena CPE 2.3:
--   cpe:2.3 : part : vendor : product : version : update : edition :
--             language : sw_edition : target_sw : target_hw : other
-- Los CPEs de Windows Server originales tenían 12 componentes (el campo
-- 'update' estaba ausente), lo que causa fallo silencioso en el matching
-- con la NVD. Se corrigen a 13 componentes con wildcard '*' donde corresponde.
--
-- REEMPLAZO DE CPE n8n (Observación #5 — vendor no registrado en NVD):
-- El CPE 'n8n:n8n' no existe en el diccionario oficial de la NVD. Las
-- búsquedas sobre este activo devolverían cero resultados, dejándolo inerte
-- en la simulación. Se reemplaza por 'nodejs:node.js:18.0.0', el runtime
-- subyacente de n8n, que sí posee amplia cobertura de CVEs en NVD y refleja
-- fielmente la superficie de ataque real del servidor orquestador.
-- Referencia de verificación: https://nvd.nist.gov/products/cpe/search
--
-- CORRECCIÓN DE NOMENCLATURA CPE (Fase 0 de la refactorización, agosto 2026):
-- El diagnóstico previo detectó ocho identificadores defectuosos sobre los
-- veinte productos del inventario, con incidencia sobre trece de los treinta
-- activos. Cuatro figuraban en el diccionario oficial del NIST con un reemplazo
-- declarado: 'windows_server:2022', 'windows_11:22h2', 'windows_10:22h2' y
-- 'node.js:18.0.0'. Los otros cuatro no tenían ninguna entrada en el
-- diccionario: 'windows_server:2019', 'windows_server:2016',
-- 'jenkins:jenkins:2.401' y 'atlassian:confluence:8.2.0'.
-- Verificado por dos vías independientes:
--   1. API de productos de la NVD (/rest/json/cpes/2.0), campo deprecatedBy.
--   2. Registros CVE publicados por Microsoft como CNA en el repositorio
--      cvelistV5, campo containers.cna.cpeApplicability.
-- Evidencia: deprecaciones_cpe.csv y 30_activos.csv de la Fase 0.
-- La forma anterior producía cero correlaciones en los niveles N1, N2 y N3 de
-- la cascada de correlación. Con la corrección, los cinco productos de Microsoft
-- pasaron de 0 a 1.766 correlaciones en el nivel N2 (CPE declarado por la propia
-- CNA dentro del registro CVE), sobre los 23.144 registros publicados entre mayo
-- y julio de 2026. El nivel N2 se resuelve sobre el corpus local y no depende de
-- la API, de modo que la corrección de nomenclatura es su única causa posible.
-- NOTA (20/09/2026): la cifra "de 196 a 1.962" que figuraba aquí queda retirada.
-- El 1.962 no existe en los archivos de la Fase 0 y la comparación no aislaba el
-- efecto de la corrección, porque entre ambas mediciones cambió también el
-- parámetro de consulta a la API.
-- Ver sección 2.3 — no univocidad del identificador CPE.
-- =============================================================================

INSERT INTO activos (hostname, alias, cpe, criticidad_id, exposicion_internet) VALUES

-- -------------------------------------------------------------------------
-- 3 ACTIVOS CRÍTICOS — criticidad_id = 4 (10% del inventario)
-- -------------------------------------------------------------------------
-- Servidor de base de datos principal: activo de mayor criticidad operativa.
-- Contiene datos de negocio; su compromiso implica pérdida de confidencialidad
-- e integridad total. Red interna — no expuesto directamente a Internet.
('srv-db-main', 'PostgreSQL 16 - Base de Datos Principal',
 'cpe:2.3:a:postgresql:postgresql:16.0:*:*:*:*:*:*:*',
 4, FALSE),

-- Servidor ERP: sistema núcleo de gestión empresarial. Clasificado como
-- "Crown Jewel" según el marco de priorización de activos críticos (sección 3.4).
('srv-erp-core', 'Servidor ERP Core (Crown Jewel)',
 'cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*',
 4, FALSE),

-- Firewall de borde: único activo crítico expuesto a Internet. Su compromiso
-- afecta la segmentación perimetral completa de la organización.
('fw-edge-01', 'Firewall Perimetral - Edge 01',
 'cpe:2.3:o:cisco:ios:15.4:*:*:*:*:*:*:*',
 4, TRUE),

-- -------------------------------------------------------------------------
-- 6 ACTIVOS ALTOS — criticidad_id = 3 (20% del inventario)
-- -------------------------------------------------------------------------
-- Servidores web de producción: superficie de ataque directa desde Internet.
-- Apache 2.4.50 tiene CVEs documentados de alta severidad en NVD (ej. CVE-2021-41773).
('srv-web-prod1', 'Servidor Web Producción 1',
 'cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*',
 3, TRUE),

('srv-web-prod2', 'Servidor Web Producción 2',
 'cpe:2.3:a:apache:http_server:2.4.50:*:*:*:*:*:*:*',
 3, TRUE),

-- Controladores de dominio Active Directory: infraestructura de identidad crítica.
-- CORRECCIÓN CPE (Observación #4): se añade componente 'update' faltante.
-- CPE original (12 componentes): 'cpe:2.3:o:microsoft:windows_server:2022:-:*:*:*:*:*:*:*'
-- CPE corregido (13 componentes): campo 'update' reemplazado por wildcard '*'.
('srv-ad-01', 'Active Directory - Controlador Dominio 01',
 'cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*',
 3, FALSE),

('srv-ad-02', 'Active Directory - Controlador Dominio 02',
 'cpe:2.3:o:microsoft:windows_server_2022:-:*:*:*:*:*:*:*',
 3, FALSE),

-- Servidor orquestador n8n.
-- CORRECCIÓN CPE (Observación #5): 'n8n:n8n' no existe en NVD.
-- Se reemplaza por Node.js 18 LTS (runtime subyacente de n8n).
-- Esto refleja fielmente la superficie de ataque real del servidor
-- y garantiza cobertura de CVEs en las consultas a la API NVD en Fase 2.
('srv-n8n-worker', 'Servidor n8n - Workflow Automation',
 'cpe:2.3:a:nodejs:node.js:18.0.0:*:*:*:*:*:*:*',
 3, FALSE),

-- Réplica de base de datos: menor criticidad que el primario, pero sigue
-- conteniendo datos sensibles de negocio. Red interna.
('srv-db-replica', 'PostgreSQL - Réplica Base de Datos',
 'cpe:2.3:a:postgresql:postgresql:16.0:*:*:*:*:*:*:*',
 3, FALSE),

-- -------------------------------------------------------------------------
-- 12 ACTIVOS MEDIOS — criticidad_id = 2 (40% del inventario)
-- -------------------------------------------------------------------------
-- Gateway VPN: acceso remoto corporativo. Expuesto a Internet por diseño.
('srv-vpn-gw', 'VPN Gateway - Acceso Remoto',
 'cpe:2.3:a:openvpn:openvpn:2.5.4:*:*:*:*:*:*:*',
 2, TRUE),

-- Relay de correo: servicio de email saliente. Expuesto a Internet.
-- Exim 4.95 posee CVEs de severidad alta en NVD (ej. CVE-2022-37452).
('srv-mail-relay', 'Servidor Relay de Correo',
 'cpe:2.3:a:exim:exim:4.95:*:*:*:*:*:*:*',
 2, TRUE),

-- Estaciones de desarrollo: Ubuntu 22.04 LTS en red interna.
('ws-dev-01', 'Estación Desarrollo 01',
 'cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*',
 2, FALSE),

('ws-dev-02', 'Estación Desarrollo 02',
 'cpe:2.3:o:canonical:ubuntu_linux:22.04:*:*:*:lts:*:*:*',
 2, FALSE),

-- Estación de desarrollo Windows 11.
('ws-dev-03', 'Estación Desarrollo 03',
 'cpe:2.3:o:microsoft:windows_11_22h2:-:*:*:*:*:*:*:*',
 2, FALSE),

-- Servidor CI/CD: pipeline de integración continua. Jenkins 2.401.
('srv-ci-cd', 'Servidor CI/CD - Integración Continua',
 'cpe:2.3:a:jenkins:jenkins:2.401:*:*:*:*:*:*:*',
 2, FALSE),

-- Repositorio de código fuente. GitLab 16.0.
('srv-git-repo', 'Servidor Git - Repositorio Código Fuente',
 'cpe:2.3:a:gitlab:gitlab:16.0.0:*:*:*:*:*:*:*',
 2, FALSE),

-- Servidor de monitoreo de infraestructura. Zabbix 6.0 LTS.
('srv-monitor-01', 'Servidor Monitoreo - Observabilidad',
 'cpe:2.3:a:zabbix:zabbix:6.0.0:*:*:*:*:*:*:*',
 2, FALSE),

-- Stack de logging centralizado. Elasticsearch 8.8.
('srv-log-01', 'Servidor Logs - SIEM Centralizado',
 'cpe:2.3:a:elastic:elasticsearch:8.8.0:*:*:*:*:*:*:*',
 2, FALSE),

-- Servidor de respaldo. Debian 11 (Bullseye).
('srv-backup-01', 'Servidor Backup - Respaldo Centralizado',
 'cpe:2.3:o:debian:debian_linux:11.0:*:*:*:*:*:*:*',
 2, FALSE),

-- Servidores de archivos Windows Server 2019.
-- CORRECCIÓN CPE (Observación #4): misma corrección que Windows Server 2022.
-- CPE original (12 componentes): 'cpe:2.3:o:microsoft:windows_server:2019:-:*:*:*:*:*:*:*'
-- CPE corregido (13 componentes): wildcard '*' en campo 'update'.
('srv-fs-01', 'Servidor Archivos (File Server) 01',
 'cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*',
 2, FALSE),

('srv-fs-02', 'Servidor Archivos (File Server) 02',
 'cpe:2.3:o:microsoft:windows_server_2019:-:*:*:*:*:*:*:*',
 2, FALSE),

-- -------------------------------------------------------------------------
-- 9 ACTIVOS BAJOS — criticidad_id = 1 (30% del inventario)
-- -------------------------------------------------------------------------
-- Wiki pública: única exposición a Internet en este segmento de criticidad.
-- Confluence 8.2 tiene CVEs activos en NVD. Accesible externamente.
('srv-wiki-pub', 'Wiki Pública - Documentación',
 'cpe:2.3:a:atlassian:confluence:8.2.0:*:*:*:*:*:*:*',
 1, TRUE),

-- Estaciones de trabajo de RRHH y Finanzas: Windows 10 22H2.
('ws-hr-01', 'Estación RRHH 01',
 'cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:*:*',
 1, FALSE),

('ws-hr-02', 'Estación RRHH 02',
 'cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:*:*',
 1, FALSE),

('ws-finance-01', 'Estación Finanzas 01',
 'cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:*:*',
 1, FALSE),

('ws-finance-02', 'Estación Finanzas 02',
 'cpe:2.3:o:microsoft:windows_10_22h2:-:*:*:*:*:*:*:*',
 1, FALSE),

-- Estaciones de trabajo de Marketing: macOS Ventura 13.0.
('ws-mkt-01', 'Estación Marketing 01',
 'cpe:2.3:o:apple:macos:13.0:*:*:*:*:*:*:*',
 1, FALSE),

('ws-mkt-02', 'Estación Marketing 02',
 'cpe:2.3:o:apple:macos:13.0:*:*:*:*:*:*:*',
 1, FALSE),

-- Servidor de impresión. Windows Server 2016.
-- CORRECCIÓN CPE (Observación #4): misma corrección que 2019 y 2022.
('srv-print-01', 'Servidor Impresión - Print Server',
 'cpe:2.3:o:microsoft:windows_server_2016:-:*:*:*:*:*:*:*',
 1, FALSE),

-- Servidor de pruebas. Ubuntu 20.04 LTS (Focal Fossa).
('srv-test-01', 'Servidor Testing - QA',
 'cpe:2.3:o:canonical:ubuntu_linux:20.04:*:*:*:lts:*:*:*',
 1, FALSE);


-- =============================================================================
-- VERIFICACIÓN DE DISTRIBUCIÓN (queries de control para auditoría)
-- Ejecutar manualmente para confirmar integridad del inventario cargado.
-- =============================================================================

-- Distribución por criticidad (esperado: 3/6/12/9)
-- SELECT criticidad_id, COUNT(*) FROM activos GROUP BY criticidad_id ORDER BY criticidad_id DESC;

-- Distribución por exposición (esperado: TRUE=6, FALSE=24)
-- SELECT exposicion_internet, COUNT(*) FROM activos GROUP BY exposicion_internet;

-- Total de activos (esperado: 30)
-- SELECT COUNT(*) FROM activos;


-- =============================================================================
-- PASO 5.1 — ESTRUCTURAS DE LA FASE 5: REEVALUACIÓN DIFERIDA
--
-- Incorporado en la sesión del 01/09/2026. Fundamento: apartados 15.8 y 16 de
-- la Propuesta de Refactorización.
--
-- Estas estructuras sostienen la medición de H2 reformulada (15.4): el IRC
-- observado el día de la detección resultó muy bajo (máximo 0,2293), y la
-- pregunta es si habría cruzado el umbral de 0,40 más tarde, una vez que los
-- insumos maduraron. Responderla exige comparar el índice de la detección
-- contra el índice recalculado con datos maduros.
--
-- Principio de diseño: NINGUNA columna original se sobrescribe. La comparación
-- entre el valor de la detección y el valor maduro es el instrumento de
-- medición; destruir el primero invalidaría la medición. Es el mismo criterio
-- con que se creó fuente_correlacion_final.
--
-- Las escribe un workflow n8n independiente ('Fase 5 - Reevaluacion Diferida'),
-- de disparo manual, que no comparte nodos ni columnas de escritura con el
-- pipeline principal congelado el 29/08/2026.
-- =============================================================================


-- -----------------------------------------------------------------------------
-- TABLA: epss_serie_diaria
-- Serie diaria de EPSS por CVE, obtenida con scope=time-series de la API de
-- FIRST.org en las corridas de la Fase 5.
--
-- Va en tabla propia y no en columnas de telemetria_vulnerabilidades porque el
-- dato es por CVE y por día, mientras que esa tabla tiene una fila por par
-- CVE-activo. EPSS puntúa vulnerabilidades, no activos: un mismo CVE
-- correlacionado con tres activos comparte una sola serie.
--
-- DATO PERECEDERO: la API entrega únicamente los últimos 30 días y la ventana
-- se desplaza con el calendario. Lo que no se persista en una corrida no se
-- recupera. De ahí las dos corridas planificadas (20/09 y cierre de campaña).
-- -----------------------------------------------------------------------------

CREATE TABLE IF NOT EXISTS epss_serie_diaria (
    id              SERIAL PRIMARY KEY,
    cve_id          VARCHAR(20) NOT NULL,
    fecha           DATE NOT NULL,
    epss_score      NUMERIC(6,5) CHECK (epss_score BETWEEN 0 AND 1),
    epss_percentil  NUMERIC(6,5) CHECK (epss_percentil BETWEEN 0 AND 1),
    fecha_captura   TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'UTC'),
    CONSTRAINT unique_cve_fecha UNIQUE (cve_id, fecha)
);

-- Sin clave foránea contra telemetria_vulnerabilidades: cve_id no es única en
-- esa tabla, que tiene una fila por par CVE-activo. El vínculo se resuelve por
-- JOIN sobre cve_id.
--
-- La restricción unique_cve_fecha no es decorativa: habilita el
-- ON CONFLICT (cve_id, fecha) DO NOTHING del workflow, que es lo que hace la
-- captura idempotente y permite ejecutarla varias veces sin duplicar filas.

COMMENT ON TABLE epss_serie_diaria IS
    'Serie diaria de EPSS por CVE, obtenida con scope=time-series en las '
    'corridas de la Fase 5. Dato perecedero: la API entrega solo 30 dias. Una '
    'fila por CVE y por dia, no por par CVE-activo, porque EPSS puntua '
    'vulnerabilidades y no activos.';

COMMENT ON COLUMN epss_serie_diaria.epss_score IS
    'Cinco decimales, la precision de la fuente. Mayor que la de '
    'telemetria_vulnerabilidades.epss_score porque aqui no hay comparacion '
    'pareada contra un valor previo: es la serie completa, y cuatro decimales '
    'dejarian una sola cifra significativa en los CVE de score mas bajo.';

COMMENT ON COLUMN epss_serie_diaria.fecha_captura IS
    'Momento en que se ejecuto la corrida de Fase 5, en UTC. Rastro de '
    'auditoria: permite ubicar el borde superior de la serie. El score del dia '
    'en curso llega en la raiz de la respuesta y la serie arranca en D-1.';


-- -----------------------------------------------------------------------------
-- AMPLIACIÓN: telemetria_vulnerabilidades — columnas del recálculo diferido
--
-- Se agregan como ALTER TABLE y no dentro del CREATE TABLE original para dejar
-- visible que son posteriores al congelamiento del artefacto y que el pipeline
-- principal no las escribe. Son anulables y sin DEFAULT, de modo que no alteran
-- ninguna de las sentencias del flujo congelado.
--
-- No se crean columnas para valores derivados —IRC diario, fecha de cruce del
-- umbral, pico de la curva—: se calculan por consulta al momento del análisis.
-- Persistir conclusiones duplica información y habilita desincronización (RG1).
-- -----------------------------------------------------------------------------

ALTER TABLE telemetria_vulnerabilidades
    ADD COLUMN IF NOT EXISTS irc_score_final         NUMERIC(5,4),
    ADD COLUMN IF NOT EXISTS epss_score_final        NUMERIC(5,4),
    ADD COLUMN IF NOT EXISTS cvss_score_final        NUMERIC(4,2),
    ADD COLUMN IF NOT EXISTS kev_status_final        BOOLEAN,
    ADD COLUMN IF NOT EXISTS kev_fecha_agregado      DATE,
    ADD COLUMN IF NOT EXISTS ssvc_exploitation_final VARCHAR(10);

-- ADD CONSTRAINT no admite IF NOT EXISTS. En una base ya inicializada, estas
-- cuatro sentencias fallan con 'constraint ... already exists'; es inocuo y
-- significa que las restricciones ya estaban aplicadas.

ALTER TABLE telemetria_vulnerabilidades
    ADD CONSTRAINT chk_irc_final  CHECK (irc_score_final  BETWEEN 0 AND 1),
    ADD CONSTRAINT chk_epss_final CHECK (epss_score_final BETWEEN 0 AND 1),
    ADD CONSTRAINT chk_cvss_final CHECK (cvss_score_final BETWEEN 0 AND 10),
    ADD CONSTRAINT chk_ssvc_final CHECK (ssvc_exploitation_final IN ('none','poc','active'));

COMMENT ON COLUMN telemetria_vulnerabilidades.irc_score_final IS
    'IRC recalculado con datos maduros en las corridas de Fase 5 (15.8). NO '
    'sobrescribe irc_score, que conserva el valor del dia de la deteccion: la '
    'comparacion entre ambos es el instrumento de medicion de H2 reformulada '
    '(15.4).';

COMMENT ON COLUMN telemetria_vulnerabilidades.epss_score_final IS
    'EPSS del ultimo dia disponible en la corrida de Fase 5. Misma precision '
    'que epss_score, con la que se compara directamente: una escala distinta '
    'introduciria ruido de redondeo en la diferencia. El valor con la precision '
    'completa de la fuente esta en epss_serie_diaria.';

COMMENT ON COLUMN telemetria_vulnerabilidades.cvss_score_final IS
    'CVSS al cierre de campana. LIMITACION DECLARADA: la API 2.0 de la NVD no '
    'expone historial de revisiones, solo el estado actual. Se dispone de dos '
    'puntos, deteccion y cierre, no de una serie. La curva diaria del IRC '
    'aplica este valor de forma retroactiva como constante. Criterio de '
    'seleccion: primer elemento del arreglo de metricas, sin preferir la fuente '
    'Primary, replicando el criterio del flujo congelado.';

COMMENT ON COLUMN telemetria_vulnerabilidades.kev_status_final IS
    'Pertenencia al catalogo KEV al cierre de campana. Se obtiene del campo '
    'cisaExploitAdd de la respuesta de la NVD, que solo esta presente si el CVE '
    'pertenece al catalogo; no requiere consulta separada a CISA.';

COMMENT ON COLUMN telemetria_vulnerabilidades.kev_fecha_agregado IS
    'Campo cisaExploitAdd de la respuesta de la NVD, equivalente al dateAdded '
    'del catalogo KEV de CISA. Permite ubicar en el calendario la transicion de '
    'kev_status y reconstruir el componente KEV del IRC diario, que pesa 0,30 '
    'en la formula de la seccion 3.6.';

COMMENT ON COLUMN telemetria_vulnerabilidades.ssvc_exploitation_final IS
    'Punto de decision exploitation del contenedor ADP de CISA al cierre, '
    'tomado de metrics.ssvcV203 en la respuesta de la NVD. Insumo del analisis '
    'contrafactico de la zona ciega de kev_status, que colapsa poc y none en un '
    'mismo valor (R7). NO modifica la formula del IRC: el cambio de pesos fue '
    'descartado en 15.4.';


-- =============================================================================
-- VERIFICACIÓN DE LAS ESTRUCTURAS DE FASE 5 (queries de control)
-- Ejecutar manualmente tras la inicialización.
-- =============================================================================

-- Columnas del recálculo creadas (esperado: 6 filas)
-- SELECT column_name, data_type, numeric_precision, numeric_scale
-- FROM information_schema.columns
-- WHERE table_name = 'telemetria_vulnerabilidades' AND column_name LIKE '%final%'
--    OR column_name = 'kev_fecha_agregado';

-- Tabla de la serie creada y vacía en una base recién inicializada (esperado: 0)
-- SELECT COUNT(*) FROM epss_serie_diaria;

-- Estado del recálculo tras una corrida de Fase 5
-- SELECT COUNT(*) AS filas, COUNT(irc_score_final) AS con_irc,
--        MIN(irc_score) AS orig_min, MAX(irc_score) AS orig_max,
--        MIN(irc_score_final) AS final_min, MAX(irc_score_final) AS final_max
-- FROM telemetria_vulnerabilidades;
