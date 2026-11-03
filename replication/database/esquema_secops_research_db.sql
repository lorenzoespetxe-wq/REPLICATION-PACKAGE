--
-- PostgreSQL database dump
--

\restrict OLahkB0AcXxHTHK5M5T8hX5TVaW4yTgmHGfoKEjYJPfOOXrUmKb7eqYSMeXEKhq

-- Dumped from database version 16.13 (Debian 16.13-1.pgdg13+1)
-- Dumped by pg_dump version 16.13 (Debian 16.13-1.pgdg13+1)

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: activos; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.activos (
    id integer NOT NULL,
    hostname character varying(100) NOT NULL,
    alias character varying(200),
    cpe character varying(255) NOT NULL,
    criticidad_id integer NOT NULL,
    exposicion_internet boolean NOT NULL,
    created_at timestamp without time zone DEFAULT CURRENT_TIMESTAMP
);


--
-- Name: TABLE activos; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.activos IS 'Inventario simulado de 30 activos tecnológicos. Representa la CMDB de la organización en el entorno controlado de la PoC. Sección 3.4 de la tesis.';


--
-- Name: COLUMN activos.alias; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.activos.alias IS 'Alias descriptivo del activo para visualización en frontend. Nombre legible que reemplaza al hostname técnico en la UI.';


--
-- Name: COLUMN activos.cpe; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.activos.cpe IS 'Identificador CPE 2.3 con 13 componentes exactos según NIST IR 7695. Vector de correlación con la API v2.0 de la NVD en Fase 2.';


--
-- Name: COLUMN activos.criticidad_id; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.activos.criticidad_id IS 'FK a criticidad_niveles. Nivel ordinal: 1=Baja, 2=Media, 3=Alta, 4=Crítica. Distribución: 9-12-6-3 activos respectivamente (sección 3.4). Usar JOIN criticidad_niveles en queries analíticas del Capítulo 5.';


--
-- Name: COLUMN activos.exposicion_internet; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.activos.exposicion_internet IS 'TRUE = accesible desde Internet (DMZ). FALSE = red interna. Distribución: 6 TRUE / 24 FALSE (20%/80%, sección 3.4).';


--
-- Name: activos_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.activos_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: activos_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.activos_id_seq OWNED BY public.activos.id;


--
-- Name: auditoria_acciones; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.auditoria_acciones (
    id integer NOT NULL,
    accion character varying(50) NOT NULL,
    tipo_entidad character varying(50) NOT NULL,
    entidad_id integer NOT NULL,
    "timestamp" timestamp without time zone DEFAULT now() NOT NULL,
    metadata_json jsonb
);


--
-- Name: TABLE auditoria_acciones; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.auditoria_acciones IS 'Log de auditoría de acciones humanas: re-envíos, cambios de estado, transiciones HITL. C-11.';


--
-- Name: COLUMN auditoria_acciones.accion; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.auditoria_acciones.accion IS 'RESEND, STATUS_CHANGE, HITL_TRANSITION';


--
-- Name: COLUMN auditoria_acciones.tipo_entidad; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.auditoria_acciones.tipo_entidad IS 'Tipo de entidad afectada: vulnerabilidad';


--
-- Name: COLUMN auditoria_acciones.metadata_json; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.auditoria_acciones.metadata_json IS 'Datos contextuales de la acción en formato JSON (JSONB).';


--
-- Name: auditoria_acciones_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.auditoria_acciones_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: auditoria_acciones_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.auditoria_acciones_id_seq OWNED BY public.auditoria_acciones.id;


--
-- Name: criticidad_niveles; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.criticidad_niveles (
    id integer NOT NULL,
    nombre character varying(20) NOT NULL,
    descripcion text,
    peso_normalizacion numeric(5,4) GENERATED ALWAYS AS (((id)::numeric / 4.0)) STORED
);


--
-- Name: TABLE criticidad_niveles; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.criticidad_niveles IS 'Tabla de referencia para la escala ordinal de criticidad organizacional. Sección 3.5 de la tesis. La columna peso_normalizacion provee CRITnorm = id/4 listo para el cálculo del IRC en el pipeline n8n.';


--
-- Name: epss_serie_diaria; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.epss_serie_diaria (
    id integer NOT NULL,
    cve_id character varying(20) NOT NULL,
    fecha date NOT NULL,
    epss_score numeric(6,5),
    epss_percentil numeric(6,5),
    fecha_captura timestamp without time zone DEFAULT (now() AT TIME ZONE 'UTC'::text) NOT NULL,
    CONSTRAINT epss_serie_diaria_epss_percentil_check CHECK (((epss_percentil >= (0)::numeric) AND (epss_percentil <= (1)::numeric))),
    CONSTRAINT epss_serie_diaria_epss_score_check CHECK (((epss_score >= (0)::numeric) AND (epss_score <= (1)::numeric)))
);


--
-- Name: TABLE epss_serie_diaria; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.epss_serie_diaria IS 'Serie diaria de EPSS por CVE, obtenida con scope=time-series en la corrida unica de la Fase 5. Dato perecedero: la API entrega solo 30 dias. Una fila por CVE y por dia, no por par CVE-activo, porque EPSS puntua vulnerabilidades y no activos.';


--
-- Name: COLUMN epss_serie_diaria.epss_score; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.epss_serie_diaria.epss_score IS 'Cinco decimales, la precision de la fuente. Mayor que la de telemetria_vulnerabilidades.epss_score porque aqui no hay comparacion pareada contra un valor previo: es la serie completa, y cuatro decimales dejarian una sola cifra significativa en los CVE de score mas bajo.';


--
-- Name: COLUMN epss_serie_diaria.fecha_captura; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.epss_serie_diaria.fecha_captura IS 'Momento en que se ejecuto la corrida de Fase 5, en UTC. Rastro de auditoria: permite ubicar el borde superior de la serie, que la API entrega hasta D-1.';


--
-- Name: epss_serie_diaria_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.epss_serie_diaria_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: epss_serie_diaria_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.epss_serie_diaria_id_seq OWNED BY public.epss_serie_diaria.id;


--
-- Name: telemetria_vulnerabilidades; Type: TABLE; Schema: public; Owner: -
--

CREATE TABLE public.telemetria_vulnerabilidades (
    id integer NOT NULL,
    cve_id character varying(20) NOT NULL,
    activo_id integer NOT NULL,
    cvss_score numeric(4,2),
    epss_score numeric(5,4),
    kev_status boolean,
    irc_score numeric(5,4),
    prioridad character varying(20),
    fecha_publicacion_nvd timestamp without time zone NOT NULL,
    fecha_ingesta_pipeline timestamp without time zone,
    fecha_alerta_generada timestamp without time zone,
    message_id character varying(255),
    cve_description text,
    nvd_url character varying(512),
    epss_url character varying(512),
    fecha_hitl_update timestamp without time zone,
    fecha_actualizacion_datos timestamp without time zone,
    estado character varying(30) DEFAULT 'DETECTADA'::character varying NOT NULL,
    fuente_correlacion character varying(20),
    nivel_confianza character varying(10),
    fecha_modificacion_nvd timestamp without time zone,
    ssvc_exploitation character varying(10),
    fuente_correlacion_final character varying(20),
    fecha_enriquecimiento_nvd timestamp without time zone,
    fecha_promocion_detectada timestamp without time zone,
    irc_score_final numeric(5,4),
    epss_score_final numeric(5,4),
    cvss_score_final numeric(4,2),
    kev_status_final boolean,
    kev_fecha_agregado date,
    ssvc_exploitation_final character varying(10),
    CONSTRAINT chk_cvss_final CHECK (((cvss_score_final >= (0)::numeric) AND (cvss_score_final <= (10)::numeric))),
    CONSTRAINT chk_epss_final CHECK (((epss_score_final >= (0)::numeric) AND (epss_score_final <= (1)::numeric))),
    CONSTRAINT chk_fuente_correlacion CHECK (((fuente_correlacion)::text = ANY ((ARRAY['NVD'::character varying, 'CNA'::character varying, 'ADP'::character varying, 'HEURISTICA'::character varying])::text[]))),
    CONSTRAINT chk_irc_final CHECK (((irc_score_final >= (0)::numeric) AND (irc_score_final <= (1)::numeric))),
    CONSTRAINT chk_nivel_confianza CHECK (((nivel_confianza)::text = ANY ((ARRAY['FORMAL'::character varying, 'INFERIDA'::character varying])::text[]))),
    CONSTRAINT chk_ssvc_exploitation CHECK (((ssvc_exploitation)::text = ANY ((ARRAY['none'::character varying, 'poc'::character varying, 'active'::character varying])::text[]))),
    CONSTRAINT chk_ssvc_final CHECK (((ssvc_exploitation_final)::text = ANY ((ARRAY['none'::character varying, 'poc'::character varying, 'active'::character varying])::text[]))),
    CONSTRAINT telemetria_vulnerabilidades_cvss_score_check CHECK (((cvss_score >= (0)::numeric) AND (cvss_score <= (10)::numeric))),
    CONSTRAINT telemetria_vulnerabilidades_epss_score_check CHECK (((epss_score >= (0)::numeric) AND (epss_score <= (1)::numeric))),
    CONSTRAINT telemetria_vulnerabilidades_estado_check CHECK (((estado)::text = ANY ((ARRAY['DETECTADA'::character varying, 'NOTIFICADA'::character varying, 'INFORMATIVA'::character varying, 'EN_REVISION'::character varying, 'REMEDIADA'::character varying, 'DESCARTADA'::character varying])::text[]))),
    CONSTRAINT telemetria_vulnerabilidades_fuente_correlacion_final_check CHECK (((fuente_correlacion_final)::text = ANY ((ARRAY['NVD'::character varying, 'CNA'::character varying, 'ADP'::character varying])::text[]))),
    CONSTRAINT telemetria_vulnerabilidades_irc_score_check CHECK (((irc_score >= (0)::numeric) AND (irc_score <= (1)::numeric))),
    CONSTRAINT telemetria_vulnerabilidades_prioridad_check CHECK (((prioridad)::text = ANY ((ARRAY['CRITICA'::character varying, 'ALTA'::character varying, 'INFORMATIVA'::character varying])::text[])))
);


--
-- Name: TABLE telemetria_vulnerabilidades; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON TABLE public.telemetria_vulnerabilidades IS 'Registro histórico de vulnerabilidades procesadas por el pipeline. Fuente primaria de datos empíricos para el benchmarking del MTTD. Secciones 2.8, 3.7 y 3.11 de la tesis.';


--
-- Name: COLUMN telemetria_vulnerabilidades.irc_score; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.telemetria_vulnerabilidades.irc_score IS 'Índice de Riesgo Compuesto calculado según fórmula de sección 3.6: IRC = 0.15*CVSSnorm + 0.25*EPSS + 0.30*KEV + 0.20*CRITnorm + 0.10*EXP';


--
-- Name: COLUMN telemetria_vulnerabilidades.fecha_hitl_update; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.telemetria_vulnerabilidades.fecha_hitl_update IS 'Timestamp de la última transición HITL (EN_REVISION, REMEDIADA, DESCARTADA). C-10.';


--
-- Name: COLUMN telemetria_vulnerabilidades.estado; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.telemetria_vulnerabilidades.estado IS 'Estado actual en el ciclo de vida del procesamiento. Incluye pipeline (DETECTADA → NOTIFICADA/INFORMATIVA) y estados HITL (EN_REVISION → REMEDIADA, DESCARTADA). C-10.';


--
-- Name: COLUMN telemetria_vulnerabilidades.irc_score_final; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.telemetria_vulnerabilidades.irc_score_final IS 'IRC recalculado con datos maduros en la corrida unica de Fase 5 (15.8). NO sobrescribe irc_score, que conserva el valor del dia de la deteccion: la comparacion entre ambos es el instrumento de medicion de H2 reformulada (15.4).';


--
-- Name: COLUMN telemetria_vulnerabilidades.epss_score_final; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.telemetria_vulnerabilidades.epss_score_final IS 'EPSS del ultimo dia disponible en la corrida de Fase 5. Misma precision que epss_score, con la que se compara directamente: una escala distinta introduciria ruido de redondeo en la diferencia. El valor con la precision completa de la fuente esta en epss_serie_diaria.';


--
-- Name: COLUMN telemetria_vulnerabilidades.cvss_score_final; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.telemetria_vulnerabilidades.cvss_score_final IS 'CVSS al cierre de campana. LIMITACION DECLARADA: la API 2.0 de la NVD no expone historial de revisiones, solo el estado actual. Se dispone de dos puntos, deteccion y cierre, no de una serie. La curva diaria del IRC aplica este valor de forma retroactiva como constante.';


--
-- Name: COLUMN telemetria_vulnerabilidades.kev_status_final; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.telemetria_vulnerabilidades.kev_status_final IS 'Pertenencia al catalogo KEV al cierre de campana.';


--
-- Name: COLUMN telemetria_vulnerabilidades.kev_fecha_agregado; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.telemetria_vulnerabilidades.kev_fecha_agregado IS 'Campo dateAdded del catalogo KEV de CISA. Permite ubicar en el calendario la transicion de kev_status y reconstruir el componente KEV del IRC diario, que pesa 0,30 en la formula de la seccion 3.6.';


--
-- Name: COLUMN telemetria_vulnerabilidades.ssvc_exploitation_final; Type: COMMENT; Schema: public; Owner: -
--

COMMENT ON COLUMN public.telemetria_vulnerabilidades.ssvc_exploitation_final IS 'Punto de decision exploitation del contenedor ADP de CISA al cierre. Insumo del analisis contrafactico de la zona ciega de kev_status, que colapsa poc y none en un mismo valor (R7). NO modifica la formula del IRC: el cambio de pesos fue descartado en 15.4.';


--
-- Name: telemetria_vulnerabilidades_id_seq; Type: SEQUENCE; Schema: public; Owner: -
--

CREATE SEQUENCE public.telemetria_vulnerabilidades_id_seq
    AS integer
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


--
-- Name: telemetria_vulnerabilidades_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: -
--

ALTER SEQUENCE public.telemetria_vulnerabilidades_id_seq OWNED BY public.telemetria_vulnerabilidades.id;


--
-- Name: activos id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activos ALTER COLUMN id SET DEFAULT nextval('public.activos_id_seq'::regclass);


--
-- Name: auditoria_acciones id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auditoria_acciones ALTER COLUMN id SET DEFAULT nextval('public.auditoria_acciones_id_seq'::regclass);


--
-- Name: epss_serie_diaria id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.epss_serie_diaria ALTER COLUMN id SET DEFAULT nextval('public.epss_serie_diaria_id_seq'::regclass);


--
-- Name: telemetria_vulnerabilidades id; Type: DEFAULT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.telemetria_vulnerabilidades ALTER COLUMN id SET DEFAULT nextval('public.telemetria_vulnerabilidades_id_seq'::regclass);


--
-- Name: activos activos_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activos
    ADD CONSTRAINT activos_pkey PRIMARY KEY (id);


--
-- Name: auditoria_acciones auditoria_acciones_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.auditoria_acciones
    ADD CONSTRAINT auditoria_acciones_pkey PRIMARY KEY (id);


--
-- Name: criticidad_niveles criticidad_niveles_nombre_key; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.criticidad_niveles
    ADD CONSTRAINT criticidad_niveles_nombre_key UNIQUE (nombre);


--
-- Name: criticidad_niveles criticidad_niveles_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.criticidad_niveles
    ADD CONSTRAINT criticidad_niveles_pkey PRIMARY KEY (id);


--
-- Name: epss_serie_diaria epss_serie_diaria_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.epss_serie_diaria
    ADD CONSTRAINT epss_serie_diaria_pkey PRIMARY KEY (id);


--
-- Name: telemetria_vulnerabilidades telemetria_vulnerabilidades_pkey; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.telemetria_vulnerabilidades
    ADD CONSTRAINT telemetria_vulnerabilidades_pkey PRIMARY KEY (id);


--
-- Name: telemetria_vulnerabilidades unique_activo_cve; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.telemetria_vulnerabilidades
    ADD CONSTRAINT unique_activo_cve UNIQUE (activo_id, cve_id);


--
-- Name: epss_serie_diaria unique_cve_fecha; Type: CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.epss_serie_diaria
    ADD CONSTRAINT unique_cve_fecha UNIQUE (cve_id, fecha);


--
-- Name: idx_aa_accion; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aa_accion ON public.auditoria_acciones USING btree (accion);


--
-- Name: idx_aa_entidad_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aa_entidad_id ON public.auditoria_acciones USING btree (entidad_id);


--
-- Name: idx_aa_timestamp; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aa_timestamp ON public.auditoria_acciones USING btree ("timestamp");


--
-- Name: idx_aa_tipo_entidad; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_aa_tipo_entidad ON public.auditoria_acciones USING btree (tipo_entidad);


--
-- Name: idx_activos_cpe; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_activos_cpe ON public.activos USING btree (cpe);


--
-- Name: idx_tv_activo_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tv_activo_id ON public.telemetria_vulnerabilidades USING btree (activo_id);


--
-- Name: idx_tv_cve_id; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tv_cve_id ON public.telemetria_vulnerabilidades USING btree (cve_id);


--
-- Name: idx_tv_estado; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tv_estado ON public.telemetria_vulnerabilidades USING btree (estado);


--
-- Name: idx_tv_fecha_publicacion; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tv_fecha_publicacion ON public.telemetria_vulnerabilidades USING btree (fecha_publicacion_nvd);


--
-- Name: idx_tv_prioridad; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tv_prioridad ON public.telemetria_vulnerabilidades USING btree (prioridad);


--
-- Name: idx_tv_promovidas; Type: INDEX; Schema: public; Owner: -
--

CREATE INDEX idx_tv_promovidas ON public.telemetria_vulnerabilidades USING btree (fuente_correlacion_final) WHERE (fuente_correlacion_final IS NOT NULL);


--
-- Name: activos activos_criticidad_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.activos
    ADD CONSTRAINT activos_criticidad_id_fkey FOREIGN KEY (criticidad_id) REFERENCES public.criticidad_niveles(id);


--
-- Name: telemetria_vulnerabilidades telemetria_vulnerabilidades_activo_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: -
--

ALTER TABLE ONLY public.telemetria_vulnerabilidades
    ADD CONSTRAINT telemetria_vulnerabilidades_activo_id_fkey FOREIGN KEY (activo_id) REFERENCES public.activos(id);


--
-- PostgreSQL database dump complete
--

\unrestrict OLahkB0AcXxHTHK5M5T8hX5TVaW4yTgmHGfoKEjYJPfOOXrUmKb7eqYSMeXEKhq

