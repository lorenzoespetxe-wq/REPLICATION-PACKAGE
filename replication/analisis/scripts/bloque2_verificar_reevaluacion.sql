-- Bloque 2 -- Verificacion despues de correr el flujo "Fase 5 - Reevaluacion Diferida".
-- Esperado: 3883 filas, todas con fecha_actualizacion_datos de hoy, ninguna con columnas finales nulas;
-- la serie de EPSS pasa de 1330 filas (y 732 CVE) a mas filas y 1040 CVE.
select count(*) as filas,
       count(*) filter (where fecha_actualizacion_datos >= date '2026-10-01') as actualizadas_hoy,
       count(*) filter (where epss_score_final is null) as epss_final_nulo,
       count(*) filter (where irc_score_final is null) as irc_final_nulo,
       count(*) filter (where cvss_score_final is null) as cvss_final_nulo,
       count(*) filter (where epss_score_final = 0) as epss_final_cero
from telemetria_vulnerabilidades;
select count(*) as filas_serie, count(distinct cve_id) as cves_en_serie, max(fecha) as ultima_fecha from epss_serie_diaria;
select max(fecha_actualizacion_datos) as fin_de_la_corrida from telemetria_vulnerabilidades;
