# Revisión independiente — vía formal (censo de 60 vulnerabilidades)

**Fecha:** 2026-10-04
**Revisor:** agente independiente, sin acceso a revisiones previas, a `bloque6_*`, `bloque7_*` ni a `errores_conocidos.csv`.
**Insumos usados:** `data/cleaned/bloque5_muestra_validacion/planilla_revision.csv` (filas `via == formal`, F01–F60), `data/raw/activos_inventario.csv`, registros CVE de la CNA en `data/raw/cvelistv5_cierre/cves/` (los 60 estaban disponibles localmente), `data/raw/nvd_reconsulta/configs_vulnerable_20261003.csv`, y la API pública de la NVD solo para F16–F25, que no figuran en la foto de cierre (ver sesgos, punto 3).

## 1. Resultado en una mirada

| unidad | correcto | error | dudoso | total |
|---|---|---|---|---|
| Vulnerabilidades | 50 | 10 | 0 | 60 |
| Producto × vulnerabilidad | 159 | 10 | 0 | 169 |
| Pares activo × vulnerabilidad | 357 | 20 | 0 | 377 |

*Nota.* Los diez errores son de un solo tipo y un solo mecanismo: F16–F25, diez vulnerabilidades de Google Chrome para Mac en las que la NVD declara `cpe:2.3:o:apple:macos` como plataforma (`vulnerable: false`) y la vía formal la tomó como producto afectado. Producen 20 pares erróneos (ws-mkt-01 y ws-mkt-02). Todas las correlaciones con Windows coinciden con el aviso del fabricante en producto; ninguna pudo verificarse en versión porque el inventario no registra el build. De los 159 «correcto», 43 productos (79 pares) llevan asterisco: el fabricante los lista como afectados, pero la explotación depende de un rol o componente opcional que el inventario no registra (sección 4).

## 2. Criterios aplicados cuando el inventario no tiene el dato

1. **Versión ausente («-») en Windows.** El CPE del inventario codifica la línea de producto (Windows 10 22H2, Server 2016/2019/2022) pero no el build. Microsoft expresa el rango afectado por build (p. ej., `10.0.19045.0` hasta `10.0.19045.7725` excluido). Respondo la pregunta 2 como **no verificable** y, para el veredicto, **presumo que el activo está sin el parche**: todas las vulnerabilidades de Microsoft revisadas se publicaron el mismo día que su corrección (08/09/2026), de modo que ningún activo podía tener el build corregido antes de la publicación, y el inventario no registra parcheo posterior. Bajo ese supuesto el par es **correcto**. Si el supuesto se levanta, la versión de esos pares pasa a ser indeterminada, no errónea.
2. **Producto: coincidencia exacta de línea.** Exijo que el aviso nombre la misma línea de producto que el inventario («Windows Server 2019» o su variante «Server Core installation» cuentan; «Windows 10 Version 1809» no cuenta como Windows 10 22H2). No acepto coincidencias por familia.
3. **Plataforma.** Si el producto del inventario aparece solo como entorno de ejecución de otro producto (en la NVD, `vulnerable: false` dentro de un nodo AND; en el aviso, «Chrome on Mac»), el par es **error de tipo plataforma**, aunque el activo pudiera tener instalado el producto afectado: el inventario no registra software de aplicación, así que nada en los datos sostiene la alerta.
4. **Roles y componentes opcionales.** Si el fabricante lista el producto como afectado pero la falla está en un rol o característica opcional (Servidor DHCP, Servicios para NFS, Message Queuing, KDC), el par se juzga **correcto a nivel de producto** (marcado `correcto*`), porque esa es la granularidad que un CPE puede expresar. El riesgo de sobre-alerta se informa aparte y no se cuenta como error.
5. **Fuente de verdad.** Para la pregunta 1 uso el registro de la CNA (el aviso del fabricante en formato estructurado: bloques `affected` y `cpeApplicability`). La configuración de la NVD la uso solo para entender por qué la vía formal correlacionó (vulnerable o plataforma).

## 3. Tabla por producto

*Nota.* «Pares» es la cantidad de activos con ese producto dentro de la columna `activos`. `correcto*` = correcto a nivel de producto, con exposición condicionada a un rol no registrado. Fuente: registros CNA locales al cierre; API de la NVD para F16–F25.

| id | CVE | producto del inventario | 1. ¿afectado según aviso? | 2. ¿versión en rango? | 3. veredicto | tipo de error | pares | motivo |
|---|---|---|---|---|---|---|---|---|
| F01 | CVE-2026-69266 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F01 | CVE-2026-69266 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F01 | CVE-2026-69266 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F02 | CVE-2026-69297 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F02 | CVE-2026-69297 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F02 | CVE-2026-69297 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F03 | CVE-2026-69342 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F03 | CVE-2026-69342 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F03 | CVE-2026-69342 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F04 | CVE-2026-69405 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F04 | CVE-2026-69405 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F04 | CVE-2026-69405 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F05 | CVE-2026-69412 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F05 | CVE-2026-69412 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F05 | CVE-2026-69412 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F06 | CVE-2026-69415 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F06 | CVE-2026-69415 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F06 | CVE-2026-69415 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F07 | CVE-2026-69497 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F07 | CVE-2026-69497 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F07 | CVE-2026-69497 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F08 | CVE-2026-69510 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F08 | CVE-2026-69510 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F08 | CVE-2026-69510 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F09 | CVE-2026-69620 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F09 | CVE-2026-69620 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F09 | CVE-2026-69620 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F10 | CVE-2026-69637 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F10 | CVE-2026-69637 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F10 | CVE-2026-69637 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F11 | CVE-2026-69679 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F11 | CVE-2026-69679 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F11 | CVE-2026-69679 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere el rol Servidor DHCP, no registrado en el inventario. |
| F12 | CVE-2026-77503 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F12 | CVE-2026-77503 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F12 | CVE-2026-77503 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F12 | CVE-2026-77503 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F13 | CVE-2026-78447 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F13 | CVE-2026-78447 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F13 | CVE-2026-78447 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F13 | CVE-2026-78447 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F14 | CVE-2026-78508 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F15 | CVE-2026-78516 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F16 | CVE-2026-79001 | Apple macOS 13.0 | solo como plataforma | no aplica | error | plataforma | 2 | Afecta a Google Chrome para Mac (<152.0.7977.65); la NVD marca cpe:o:apple:macos con vulnerable=false. |
| F17 | CVE-2026-79012 | Apple macOS 13.0 | solo como plataforma | no aplica | error | plataforma | 2 | Afecta a Google Chrome para Mac (<152.0.7977.65); la NVD marca cpe:o:apple:macos con vulnerable=false. |
| F18 | CVE-2026-79041 | Apple macOS 13.0 | solo como plataforma | no aplica | error | plataforma | 2 | Afecta a Google Chrome para Mac (<152.0.7977.65); la NVD marca cpe:o:apple:macos con vulnerable=false. |
| F19 | CVE-2026-79064 | Apple macOS 13.0 | solo como plataforma | no aplica | error | plataforma | 2 | Afecta a Google Chrome para Mac (<152.0.7977.65); la NVD marca cpe:o:apple:macos con vulnerable=false. |
| F20 | CVE-2026-79069 | Apple macOS 13.0 | solo como plataforma | no aplica | error | plataforma | 2 | Afecta a Google Chrome para Mac (<152.0.7977.65); la NVD marca cpe:o:apple:macos con vulnerable=false. |
| F21 | CVE-2026-79091 | Apple macOS 13.0 | solo como plataforma | no aplica | error | plataforma | 2 | Afecta a Google Chrome para Mac (<152.0.7977.65); la NVD marca cpe:o:apple:macos con vulnerable=false. |
| F22 | CVE-2026-79128 | Apple macOS 13.0 | solo como plataforma | no aplica | error | plataforma | 2 | Afecta a Google Chrome para Mac (<152.0.7977.65); la NVD marca cpe:o:apple:macos con vulnerable=false. |
| F23 | CVE-2026-79140 | Apple macOS 13.0 | solo como plataforma | no aplica | error | plataforma | 2 | Afecta a Google Chrome para Mac (<152.0.7977.65); la NVD marca cpe:o:apple:macos con vulnerable=false. |
| F24 | CVE-2026-79150 | Apple macOS 13.0 | solo como plataforma | no aplica | error | plataforma | 2 | Afecta a Google Chrome para Mac (<152.0.7977.65); la NVD marca cpe:o:apple:macos con vulnerable=false. |
| F25 | CVE-2026-79284 | Apple macOS 13.0 | solo como plataforma | no aplica | error | plataforma | 2 | Afecta a Google Chrome para Mac (<152.0.7977.65); la NVD marca cpe:o:apple:macos con vulnerable=false. |
| F26 | CVE-2026-80075 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F27 | CVE-2026-80093 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F28 | CVE-2026-80096 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F29 | CVE-2026-81354 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F30 | CVE-2026-83940 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F31 | CVE-2026-83942 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F32 | CVE-2026-83954 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F32 | CVE-2026-83954 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F32 | CVE-2026-83954 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F32 | CVE-2026-83954 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F33 | CVE-2026-83955 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F33 | CVE-2026-83955 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F33 | CVE-2026-83955 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F33 | CVE-2026-83955 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F34 | CVE-2026-83967 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F34 | CVE-2026-83967 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F34 | CVE-2026-83967 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F34 | CVE-2026-83967 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F35 | CVE-2026-83968 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F36 | CVE-2026-83969 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F36 | CVE-2026-83969 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F36 | CVE-2026-83969 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F36 | CVE-2026-83969 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F37 | CVE-2026-83970 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F37 | CVE-2026-83970 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F37 | CVE-2026-83970 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F37 | CVE-2026-83970 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F38 | CVE-2026-83971 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F38 | CVE-2026-83971 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F38 | CVE-2026-83971 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F38 | CVE-2026-83971 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F39 | CVE-2026-83972 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F39 | CVE-2026-83972 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F39 | CVE-2026-83972 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F39 | CVE-2026-83972 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F40 | CVE-2026-83974 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F40 | CVE-2026-83974 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F40 | CVE-2026-83974 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F40 | CVE-2026-83974 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F41 | CVE-2026-83975 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F41 | CVE-2026-83975 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F41 | CVE-2026-83975 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F41 | CVE-2026-83975 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F42 | CVE-2026-83976 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F42 | CVE-2026-83976 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F42 | CVE-2026-83976 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F42 | CVE-2026-83976 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F43 | CVE-2026-83977 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F43 | CVE-2026-83977 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F43 | CVE-2026-83977 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F43 | CVE-2026-83977 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F44 | CVE-2026-83978 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F44 | CVE-2026-83978 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F44 | CVE-2026-83978 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F44 | CVE-2026-83978 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F45 | CVE-2026-83979 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F45 | CVE-2026-83979 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F45 | CVE-2026-83979 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F45 | CVE-2026-83979 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F46 | CVE-2026-83980 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F46 | CVE-2026-83980 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F46 | CVE-2026-83980 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F46 | CVE-2026-83980 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F47 | CVE-2026-83981 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F47 | CVE-2026-83981 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F47 | CVE-2026-83981 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F47 | CVE-2026-83981 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F48 | CVE-2026-83982 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F48 | CVE-2026-83982 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F48 | CVE-2026-83982 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F48 | CVE-2026-83982 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F49 | CVE-2026-83985 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F49 | CVE-2026-83985 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F49 | CVE-2026-83985 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F49 | CVE-2026-83985 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F50 | CVE-2026-83986 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F50 | CVE-2026-83986 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F50 | CVE-2026-83986 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F50 | CVE-2026-83986 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F51 | CVE-2026-83987 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F51 | CVE-2026-83987 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F51 | CVE-2026-83987 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F51 | CVE-2026-83987 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F52 | CVE-2026-83989 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto* | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. Exposición: requiere Servicios para NFS, no registrado. |
| F52 | CVE-2026-83989 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: requiere Servicios para NFS, no registrado. |
| F52 | CVE-2026-83989 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: requiere Servicios para NFS, no registrado. |
| F52 | CVE-2026-83989 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere Servicios para NFS, no registrado. |
| F53 | CVE-2026-83991 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F53 | CVE-2026-83991 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F53 | CVE-2026-83991 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F54 | CVE-2026-83992 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F54 | CVE-2026-83992 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F54 | CVE-2026-83992 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F54 | CVE-2026-83992 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F55 | CVE-2026-83995 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F55 | CVE-2026-83995 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F55 | CVE-2026-83995 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F55 | CVE-2026-83995 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F56 | CVE-2026-83996 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F56 | CVE-2026-83996 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F56 | CVE-2026-83996 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F56 | CVE-2026-83996 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F57 | CVE-2026-83997 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto* | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. Exposición: requiere Message Queuing habilitado, no registrado. |
| F57 | CVE-2026-83997 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: requiere Message Queuing habilitado, no registrado. |
| F58 | CVE-2026-84001 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto* | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. Exposición: el KDC solo corre en controladores de dominio; en estaciones Windows 10 y servidores no-DC no es explotable. |
| F58 | CVE-2026-84001 | Windows Server 2016 (versión «-») | sí | no verificable | correcto* | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. Exposición: el KDC solo corre en controladores de dominio; en estaciones Windows 10 y servidores no-DC no es explotable. |
| F58 | CVE-2026-84001 | Windows Server 2019 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. Exposición: el KDC solo corre en controladores de dominio; en estaciones Windows 10 y servidores no-DC no es explotable. |
| F58 | CVE-2026-84001 | Windows Server 2022 (versión «-») | sí | no verificable | correcto* | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. Exposición: el KDC solo corre en controladores de dominio; en estaciones Windows 10 y servidores no-DC no es explotable. |
| F59 | CVE-2026-85360 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F59 | CVE-2026-85360 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F59 | CVE-2026-85360 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F59 | CVE-2026-85360 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |
| F60 | CVE-2026-85880 | Windows 10 Version 22H2 (versión «-») | sí | no verificable | correcto | — | 4 | La CNA lista «Windows 10 Version 22H2» como afectado hasta el build 10.0.19045.7725 (excl.); el inventario no registra build. |
| F60 | CVE-2026-85880 | Windows Server 2016 (versión «-») | sí | no verificable | correcto | — | 1 | La CNA lista «Windows Server 2016» como afectado hasta el build 10.0.14393.9512 (excl.); el inventario no registra build. |
| F60 | CVE-2026-85880 | Windows Server 2019 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2019» como afectado hasta el build 10.0.17763.9245 (excl.); el inventario no registra build. |
| F60 | CVE-2026-85880 | Windows Server 2022 (versión «-») | sí | no verificable | correcto | — | 2 | La CNA lista «Windows Server 2022» como afectado hasta el build 10.0.20348.5622 (excl.); el inventario no registra build. |

## 4. Totales por vulnerabilidad

*Nota.* El veredicto de la vulnerabilidad es «correcto» si todos sus productos lo son y «error» si todos son error. No hubo casos mixtos.

| id | CVE | productos correctos | productos error | productos dudosos | pares correctos | pares error | pares dudosos | veredicto de la vulnerabilidad |
|---|---|---|---|---|---|---|---|---|
| F01 | CVE-2026-69266 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F02 | CVE-2026-69297 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F03 | CVE-2026-69342 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F04 | CVE-2026-69405 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F05 | CVE-2026-69412 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F06 | CVE-2026-69415 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F07 | CVE-2026-69497 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F08 | CVE-2026-69510 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F09 | CVE-2026-69620 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F10 | CVE-2026-69637 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F11 | CVE-2026-69679 | 3 | 0 | 0 | 5 | 0 | 0 | correcto |
| F12 | CVE-2026-77503 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F13 | CVE-2026-78447 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F14 | CVE-2026-78508 | 1 | 0 | 0 | 4 | 0 | 0 | correcto |
| F15 | CVE-2026-78516 | 1 | 0 | 0 | 4 | 0 | 0 | correcto |
| F16 | CVE-2026-79001 | 0 | 1 | 0 | 0 | 2 | 0 | error |
| F17 | CVE-2026-79012 | 0 | 1 | 0 | 0 | 2 | 0 | error |
| F18 | CVE-2026-79041 | 0 | 1 | 0 | 0 | 2 | 0 | error |
| F19 | CVE-2026-79064 | 0 | 1 | 0 | 0 | 2 | 0 | error |
| F20 | CVE-2026-79069 | 0 | 1 | 0 | 0 | 2 | 0 | error |
| F21 | CVE-2026-79091 | 0 | 1 | 0 | 0 | 2 | 0 | error |
| F22 | CVE-2026-79128 | 0 | 1 | 0 | 0 | 2 | 0 | error |
| F23 | CVE-2026-79140 | 0 | 1 | 0 | 0 | 2 | 0 | error |
| F24 | CVE-2026-79150 | 0 | 1 | 0 | 0 | 2 | 0 | error |
| F25 | CVE-2026-79284 | 0 | 1 | 0 | 0 | 2 | 0 | error |
| F26 | CVE-2026-80075 | 1 | 0 | 0 | 4 | 0 | 0 | correcto |
| F27 | CVE-2026-80093 | 1 | 0 | 0 | 4 | 0 | 0 | correcto |
| F28 | CVE-2026-80096 | 1 | 0 | 0 | 4 | 0 | 0 | correcto |
| F29 | CVE-2026-81354 | 1 | 0 | 0 | 4 | 0 | 0 | correcto |
| F30 | CVE-2026-83940 | 1 | 0 | 0 | 4 | 0 | 0 | correcto |
| F31 | CVE-2026-83942 | 1 | 0 | 0 | 4 | 0 | 0 | correcto |
| F32 | CVE-2026-83954 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F33 | CVE-2026-83955 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F34 | CVE-2026-83967 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F35 | CVE-2026-83968 | 1 | 0 | 0 | 4 | 0 | 0 | correcto |
| F36 | CVE-2026-83969 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F37 | CVE-2026-83970 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F38 | CVE-2026-83971 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F39 | CVE-2026-83972 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F40 | CVE-2026-83974 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F41 | CVE-2026-83975 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F42 | CVE-2026-83976 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F43 | CVE-2026-83977 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F44 | CVE-2026-83978 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F45 | CVE-2026-83979 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F46 | CVE-2026-83980 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F47 | CVE-2026-83981 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F48 | CVE-2026-83982 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F49 | CVE-2026-83985 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F50 | CVE-2026-83986 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F51 | CVE-2026-83987 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F52 | CVE-2026-83989 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F53 | CVE-2026-83991 | 3 | 0 | 0 | 8 | 0 | 0 | correcto |
| F54 | CVE-2026-83992 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F55 | CVE-2026-83995 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F56 | CVE-2026-83996 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F57 | CVE-2026-83997 | 2 | 0 | 0 | 6 | 0 | 0 | correcto |
| F58 | CVE-2026-84001 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F59 | CVE-2026-85360 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |
| F60 | CVE-2026-85880 | 4 | 0 | 0 | 9 | 0 | 0 | correcto |

### Totales por par (columna `activos`)

| grupo | vulnerabilidades | pares | veredicto |
|---|---|---|---|
| Chrome para Mac → macOS (F16–F25) | 10 | 20 | error (plataforma) |
| Windows, producto y rango coincidentes, sin dependencia de rol | 36 | 278 | correcto (versión no verificable) |
| Windows, Servidor DHCP (F01–F11) | 11 | 55 | correcto* |
| Windows, Servicios para NFS (F52) | 1 | 9 | correcto* |
| Windows, Message Queuing (F57) | 1 | 6 | correcto* |
| Windows, Key Distribution Center (F58) | 1 | 9 | correcto* (solo srv-ad-01 y srv-ad-02 serían controladores de dominio, a juzgar por el hostname; los otros 7 pares no son explotables en la práctica) |
| **Total** | **60** | **377** | 357 correctos, 20 error |

## 5. Sesgos y problemas del encargo y del diseño de la validación

1. **La validación de Windows es casi circular.** Para los avisos de Microsoft, la configuración que publica la NVD reproduce el bloque `cpeApplicability` que entrega la propia CNA (mismos CPE, mismos rangos de build). Juzgar la vía formal contra el aviso del fabricante mide, en el caso de Microsoft, si el flujo leyó bien la NVD, no si la NVD acierta. Las 50 vulnerabilidades de Microsoft tenían una probabilidad de coincidencia cercana a uno por construcción, y el censo no puede detectar un error de la NVD que replique uno del fabricante.
2. **La pregunta de versión es vacía para 357 de 377 pares.** Todos los activos Windows tienen versión «-». El acierto de la vía formal en Windows depende entero del supuesto de que los activos no están parcheados (criterio 1). Si la tesis reporta un porcentaje de acierto, tiene que decir que es acierto en producto, no en versión. La limitación declarada de la vía (no evalúa rangos) no se pudo poner a prueba porque el inventario no tiene con qué: el único activo con versión registrada que la vía tocó es macOS 13.0, y ahí el problema es otro.
3. **La foto de cierre de la NVD no cubre las diez vulnerabilidades erróneas.** `configs_vulnerable_20261003.csv` se consultó con `pubStartDate = 2026-08-28`; F16–F25 se publicaron en la NVD el 25/08/2026 y no tienen fila. Tuve que ir a la API pública para verlas. Si la foto de cierre se usa en algún paso para validar o reconstruir la vía formal, esos diez casos quedan sin evidencia local, justo los que fallan. También indica que la ventana temporal del experimento y la de la foto no coinciden.
4. **El censo solo mira pares emitidos: no ve falsos negativos.** En varias vulnerabilidades la CNA y la NVD listan productos del inventario que la vía formal no persistió para esa CVE: F14 y F15 (Server 2016/2019/2022), F27 (2019/2022), F28 (2016/2019/2022), F29 (2019), F30 (2016/2019/2022), F31 (2019/2022), F35 (2016/2019/2022). No sé si esos pares los cubrió otra vía, si se validaron por otro lado o si faltan. Un censo de lo que la vía dijo mide precisión, no exhaustividad. Recomiendo cruzar esas omisiones antes de afirmar algo sobre cobertura. En F26 la omisión de servidores viene de la NVD (que solo lista Windows 10 22H2, aunque la CNA también lista servidores): ahí la vía siguió fielmente a su fuente.
5. **Las unidades no son independientes y el censo está concentrado.** 20 de las 60 vulnerabilidades son la misma familia (Windows Biometric Service: F13 y F32–F51), 11 son de Servidor DHCP y las diez de Chrome comparten un único mecanismo. En la práctica hay cinco o seis casos distintos, no 60. Contar por pares lo agrava: ws-mkt-01 y ws-mkt-02 tienen el mismo CPE, igual que los cuatro Windows 10 y los servidores de cada versión, así que un único juicio de producto se multiplica por 2, 4 o 5. Cualquier tasa por pares (357/377 = 94,7 %) está dominada por cuántas copias de cada producto tiene el inventario, no por el comportamiento de la vía. La unidad informativa es producto × vulnerabilidad (159/169) o, mejor, el mecanismo.
6. **El error de plataforma es sistemático, no muestral.** Los diez errores salen de una sola regla: la vía compara fabricante y producto sin mirar el atributo `vulnerable`. Cualquier CVE con un nodo AND donde macOS o Windows figure como plataforma (navegadores, clientes de videoconferencia, lectores de PDF) va a producir el mismo falso positivo. El porcentaje observado depende de cuántas CVE de ese tipo cayeron en la ventana, no de una propiedad estable de la vía. Conviene informarlo como mecanismo, con su conteo, y no como tasa.
7. **«Correcto» no es «el activo es vulnerable».** El inventario es simulado y no registra build, roles ni software instalado. El veredicto mide consistencia entre la alerta y el aviso del fabricante. Los 79 pares con dependencia de rol son el ejemplo más visible: 7 de los 9 pares del KDC (F58) caen en máquinas que, por su nombre, no son controladores de dominio, y los cuatro Windows 10 no ejecutan un KDC aunque Microsoft liste el producto.
8. **El encargo orienta al revisor.** (a) Toma «el aviso del fabricante» como verdad, pero en F16–F25 el fabricante relevante es Google, cuyo aviso no menciona macOS como producto; la pregunta 1 queda bien definida solo con un criterio de plataforma explícito. (b) El contexto ya anticipa los dos defectos de la vía («no evalúa rangos de versión ni distingue entre producto vulnerable y plataforma»), lo que dirige la búsqueda. Lo encontrado es consistente con ese aviso, pero no se llegó a ciegas.
9. **La planilla tiene vacía la columna `nombres_leidos_por_el_artefacto` en las 60 filas formales.** No afecta el juicio, pero impide reconstruir desde la planilla qué leyó el flujo en cada caso.
10. **Windows 10 22H2 está fuera del soporte general desde octubre de 2025.** Microsoft lo sigue listando porque publica parches para clientes con soporte extendido (ESU). No cambia el veredicto, pero la tesis no debería presentar esos activos como corregibles con la actualización de septiembre sin aclarar esa condición.
