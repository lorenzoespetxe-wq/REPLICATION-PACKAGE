# Revisión independiente de la muestra de la vía de inferencia (65 casos)

**Fecha:** 2026-10-04
**Revisor:** agente independiente, sin acceso a la propuesta previa de veredictos.
**Insumos usados:** `data/cleaned/bloque5_muestra_validacion/planilla_revision.csv` (filas `via == inferencia`), `data/raw/activos_inventario.csv`, registros CVE de la CNA en `data/raw/cvelistv5_cierre/` (bloques `affected`, `descriptions`, `references`) y una consulta web sobre la política de Node.js respecto de versiones fuera de soporte.
**No consultados a propósito:** `data/cleaned/bloque6_revision_inferencia/` y `data/cleaned/bloque5_muestra_validacion/errores_conocidos.csv` (este último está junto a los insumos; ver la sección de sesgos).

Antes de juzgar comparé los nombres que el artefacto leyó al ingerir (`nombres_leidos_por_el_artefacto`) con los pares fabricante/producto del registro al cierre: coinciden en los 65 casos. Los rangos de versión sí pudieron cambiar entre la ingesta y el cierre; juzgué con la copia al cierre.

## Criterios aplicados

1. **Rango de versión:** se toma el rango que declara la CNA en `affected`, leído junto con la descripción. Si ambos se contradicen, o si el fabricante declara de forma explícita que no evalúa las ramas fuera de soporte, el caso queda como *dudoso* y no como error.
2. **Versión ausente en el inventario (`-`, los diez equipos Windows):** si el registro declara afectada **toda** la línea de producto que el inventario nombra, hasta una compilación de corrección, el par se juzga **correcto** y la versión se marca *no verificable*. Esto significa «afectado salvo que esté parcheado». Es la misma condición que tiene cualquier alerta, y el inventario no promete registrar el nivel de parche. No se da por correcto cuando el registro restringe a un subconjunto de la línea, cosa que no ocurrió en la muestra.
3. **Dato estructural ausente (sistema operativo sin registrar en un activo de aplicación, edición CE/EE o Server/Data Center):** si la vulnerabilidad solo existe en una plataforma o edición que el inventario no permite confirmar, el caso queda como *dudoso (plataforma)*. Lo resolvería como **error** en el cómputo estricto, porque la alerta afirma algo que el inventario no sostiene. Lo informo además como cota.
4. **Complementos (plugins):** si el registro nombra un complemento con versionado propio y el inventario solo registra el producto anfitrión, el par es **error (complemento)**, aunque en una instalación real el complemento podría estar presente. El inventario no lo dice.
5. **Coincidencia de nombres:** *completa* cuando el producto normalizado es idéntico, o idéntico más un calificador de instalación del mismo producto (p. ej. «Server Core installation»). *Parcial* cuando una cadena contiene a la otra y el texto agregado nombra otro componente, una edición o una variante del nombre. La coincidencia del fabricante se comenta solo cuando es parcial.
6. **Configuración o rol:** no se exige (servicio DNS habilitado, Proxy-Protocol, etc.), porque el inventario no lo registra y la pregunta 4 se refiere al activo «tal como el inventario lo describe». Se anota en la sección de sesgos.

## Tabla de los 65 casos

Columnas: (1) ¿el producto figura como afectado?; (2) ¿la versión cae en el rango?; (3) tipo de coincidencia; (4) veredicto.

| id | CVE | producto (versión inv.) | (1) afectado | (2) versión | (3) coincidencia | (4) veredicto | motivo |
|---|---|---|---|---|---|---|---|
| I01 | CVE-2026-43683 | apple:macos (13.0) | sí | sí | completa | correcto | El registro declara `0 < 15.8`; 13.0 cae dentro según la lectura literal. |
| I02 | CVE-2026-64714 | apple:macos (13.0) | sí | sí | completa | correcto | Rango `0 < 14.8.8` en la entrada macOS. |
| I03 | CVE-2026-65375 | apple:macos (13.0) | sí | sí | completa | correcto | Rango `0 < 15.8`. |
| I04 | CVE-2026-65383 | apple:macos (13.0) | sí | sí | completa | correcto | Única corrección en macOS 27; rango `0 < 27`. |
| I05 | CVE-2026-84491 | apple:macos (13.0) | sí | sí | completa | correcto | Rango `0 < 27`; las demás entradas (iOS, tvOS…) no coinciden. |
| I06 | CVE-2026-84538 | apple:macos (13.0) | sí | sí | completa | correcto | Rango `0 < 15.8`. |
| I07 | CVE-2026-84621 | apple:macos (13.0) | sí | sí | completa | correcto | Rango `0 < 15.8`. |
| I08 | CVE-2026-21586 | atlassian:confluence (8.2.0) | sí (Data Center) | dudoso | parcial (edición) | dudoso | Introducida en 7.4.0; la rama 8.2 (fuera de soporte) no figura en la lista, que solo cubre ramas soportadas. |
| I09 | CVE-2026-21588 | atlassian:confluence (8.2.0) | sí (Data Center) | no | parcial (edición) | error (versión) | Introducida en 8.9.0: la 8.2.0 es anterior al defecto. |
| I10 | CVE-2026-56143 | elastic:elasticsearch (8.8.0) | sí | sí | completa | correcto | Rango 8.0.0–8.19.19. |
| I11 | CVE-2026-78607 | elastic:elasticsearch (8.8.0) | sí | sí | completa | correcto | Rango 8.0.0–8.19.18; afecta al servicio de inferencia personalizada (función opcional, ver sesgos). |
| I12 | CVE-2026-94056 | exim:exim (4.95) | sí | sí | completa | correcto | Rango 4.83 a <4.100.1; requiere Proxy-Protocol configurado. |
| I13 | CVE-2026-94057 | exim:exim (4.95) | sí | sí | completa | correcto | Rango 0 a <4.100.1. |
| I14 | CVE-2026-13210 | gitlab:gitlab (16.0.0) | sí | sí | completa | correcto | Rango 15.7 a <19.1.8, CE y EE. |
| I15 | CVE-2026-3855 | gitlab:gitlab (16.0.0) | sí | no | completa | error (versión) | El rango empieza en 18.2.7. |
| I16 | CVE-2026-86341 | gitlab:gitlab (16.0.0) | sí (solo EE) | no | completa | error (versión) | El rango empieza en 17.1; además es solo EE y el inventario no registra la edición. |
| I17 | CVE-2026-84656 | jenkins:jenkins (2.401) | sí | sí | completa (fabricante parcial: «Jenkins Project») | correcto | Afecta a 2.579 y anteriores; 2.401 está incluida. |
| I18 | CVE-2026-84660 | jenkins:jenkins (2.401) | no (es un complemento) | no verificable | parcial | error (complemento) | Afecta al complemento *Pipeline: Build Step*, no al núcleo de Jenkins que registra el inventario. |
| I19 | CVE-2026-84662 | jenkins:jenkins (2.401) | no (es un complemento) | no verificable | parcial | error (complemento) | Afecta al complemento *LDAP*, no al núcleo de Jenkins. |
| I20 | CVE-2026-69286 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | WS2016 afectado en todas las compilaciones anteriores a 10.0.14393.9512. |
| I21 | CVE-2026-69305 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem. |
| I22 | CVE-2026-69428 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem (LDAP). |
| I23 | CVE-2026-69441 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem (Windows Installer). |
| I24 | CVE-2026-69496 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem. |
| I25 | CVE-2026-69568 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem. |
| I26 | CVE-2026-69580 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem. |
| I27 | CVE-2026-69609 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem. |
| I28 | CVE-2026-69631 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem; Windows DNS (depende del rol). |
| I29 | CVE-2026-70585 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem; servicios NFS (depende del rol). |
| I30 | CVE-2026-72937 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem. |
| I31 | CVE-2026-72981 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem. |
| I32 | CVE-2026-72990 | microsoft:windows_server_2016 (-) | sí | no verificable | completa | correcto | Ídem. |
| I33 | CVE-2026-68837 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | WS2019 afectado en todas las compilaciones anteriores a 10.0.17763.9245. |
| I34 | CVE-2026-68841 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem. |
| I35 | CVE-2026-69359 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem; AD DS (rol poco probable en servidores de archivos). |
| I36 | CVE-2026-69372 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem; NFS (depende del rol). |
| I37 | CVE-2026-69470 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem. |
| I38 | CVE-2026-69579 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem; Message Queuing (componente opcional). |
| I39 | CVE-2026-69612 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem. |
| I40 | CVE-2026-69616 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem. |
| I41 | CVE-2026-69631 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem; DNS (depende del rol). |
| I42 | CVE-2026-69738 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem. |
| I43 | CVE-2026-69768 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem. |
| I44 | CVE-2026-69846 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem. |
| I45 | CVE-2026-69910 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem; Hyper-V (rol opcional). |
| I46 | CVE-2026-71345 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem. |
| I47 | CVE-2026-78453 | microsoft:windows_server_2019 (-) | sí | no verificable | completa | correcto | Ídem. |
| I48 | CVE-2026-68851 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | WS2022 afectado en todas las compilaciones anteriores a 10.0.20348.5622. |
| I49 | CVE-2026-69269 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I50 | CVE-2026-69367 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I51 | CVE-2026-69488 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I52 | CVE-2026-69498 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I53 | CVE-2026-69608 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I54 | CVE-2026-69631 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem; DNS (plausible en controladores de dominio). |
| I55 | CVE-2026-69681 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I56 | CVE-2026-69782 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem; DNS Server (depende del rol). |
| I57 | CVE-2026-69822 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I58 | CVE-2026-71337 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I59 | CVE-2026-72992 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I60 | CVE-2026-73021 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I61 | CVE-2026-77893 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem; DHCP Server (depende del rol). |
| I62 | CVE-2026-83990 | microsoft:windows_server_2022 (-) | sí | no verificable | completa | correcto | Ídem. |
| I63 | CVE-2026-48932 | nodejs:node.js (18.0.0) | sí | dudoso | parcial («node» ⊂ «nodejs», mismo producto) | dudoso | El rango literal solo nombra 22.22.3, 24.16.0 y 26.3.0, y el estado por defecto es «unaffected». La descripción dice «todas las ramas soportadas», y Node.js no evalúa las ramas fuera de soporte, como la 18. |
| I64 | CVE-2026-81830 | openvpn:openvpn (2.5.4) | sí | sí | completa | dudoso (plataforma) | Afecta solo al servicio interactivo de Windows; el inventario no registra el sistema operativo de srv-vpn-gw. |
| I65 | CVE-2026-84256 | openvpn:openvpn (2.5.4) | sí | sí | completa | dudoso (plataforma) | Afecta solo a OpenVPN sobre Windows; el sistema operativo no está registrado. |

## Totales

| Veredicto | Casos | ids |
|---|---|---|
| Correcto | 56 | I01–I07, I10–I14, I17, I20–I62 |
| Error: versión | 3 | I09, I15, I16 |
| Error: complemento | 2 | I18, I19 |
| Error: producto derivado | 0 | — |
| Error: plataforma | 0 (2 dudosos con esa causa) | — |
| Dudoso | 4 | I08 (versión, rama fuera de soporte), I63 (versión, codificación del registro), I64 e I65 (plataforma) |
| **Total** | **65** | |

**Cotas:** el criterio estricto, con los cuatro dudosos como error, da 56 correctos de 65 (86 %). El criterio favorable, con los cuatro como correctos, da 60 de 65 (92 %). Mi resolución recomendada da **58 de 65 (89 %)**: I08 e I63 cuentan como correctos, porque el fabricante declara el defecto introducido antes de la versión del inventario (I08) o declara afectadas por política las ramas fuera de soporte (I63). I64 e I65 cuentan como error de plataforma.

Sobre I63: Node.js declara que no evalúa los reportes de seguridad para versiones fuera de soporte y que los CVE nuevos incluyen esas ramas en la aplicabilidad mientras no haya información en contrario ([nodejs.org, «updates CVE for end of life»](https://nodejs.org/es/blog/vulnerability/updates-cve-for-end-of-life)). Este registro en particular no lo hace. Por eso el caso queda como dudoso y no como correcto pleno.

Ponderado por alertas (columna `pares`; Apple, WS2019 y WS2022 tienen dos activos cada uno), la proporción de correctos sube, porque los errores caen en activos únicos (Confluence, GitLab, Jenkins). Si la tesis informa la precisión por alerta y no por caso, hay que recalcularla con esa ponderación.

## Sesgos y problemas del encargo y del diseño de la validación

1. **La muestra está dominada por un caso trivial.** 43 de los 65 casos (66 %) son Windows Server, y en ellos el nombre del inventario coincide exactamente con el del registro y la versión no está registrada. En esos casos la validación no pone a prueba la lógica de inferencia: cualquier comparación de nombres los acierta. La precisión de la vía depende sobre todo de los 22 casos que no son Windows: ahí hay 5 errores y 4 dudosos en 22 (entre 59 % y 77 % correctos). Conviene informar la precisión estratificada por familia de producto, o al menos separar Windows del resto.

2. **Las versiones antiguas del inventario inflan la precisión.** La vía no mira versiones, y casi todas las versiones del inventario son viejas o están fuera de soporte (macOS 13.0, Node 18.0.0, Confluence 8.2.0, GitLab 16.0.0, Jenkins 2.401, Elasticsearch 8.8.0, Exim 4.95). Una versión vieja cae debajo de casi cualquier límite «menor que X». Los aciertos de versión son, en buena parte, una propiedad del inventario y no del método. Con un inventario de versiones actuales, la misma vía produciría muchos más errores de versión. La tesis no debería generalizar la precisión medida sin decir esto.

3. **La pregunta 2 confunde «rango declarado» con «afectado de verdad».** Los fabricantes codifican los rangos de forma desigual. Apple escribe `0 < X` aunque no evalúe las ramas que ya no reciben soporte (por eso los siete casos de macOS 13 salen correctos por lectura literal). Atlassian y Node.js listan solo ramas soportadas (I08, I63). Node.js codificó mal el rango (I63: estado por defecto «unaffected» con versiones puntuales, en contradicción con su propia descripción). Una lectura literal y una lectura de intención dan resultados distintos en al menos 9 casos (7 de Apple, I08, I63). El encargo no fijó cuál usar; yo usé la literal, salvo contradicción explícita. Si la otra revisión usó otra lectura, las diferencias vendrán de ahí y no del juicio sobre el par.

4. **No se pregunta por configuración ni por rol.** Varias vulnerabilidades solo existen si está activo un rol o una función: DNS Server, DHCP Server, Hyper-V, Message Queuing, AD DS, NFS, Proxy-Protocol de Exim, el servicio de inferencia de Elasticsearch. El inventario no registra roles, así que «correcto» aquí significa «producto y versión correctos», no «activo expuesto». Hay casos poco plausibles, como I35 (AD DS en servidores de archivos) o I38 (MSMQ), que cuento como correctos por definición. La tesis no debería leer esta precisión como proporción de alertas accionables.

5. **El inventario no tiene campos que el juicio necesita**: sistema operativo de los activos de aplicación (I64, I65), edición CE/EE de GitLab (I16) y Server/Data Center de Confluence (I08, I09), complementos instalados de Jenkins (I18, I19) y nivel de parche de Windows (43 casos). Esto no es un defecto de la vía de inferencia, sino de la descripción del activo. Pero el encargo pide juzgar «tal como el inventario lo describe», y con eso los resultados dependen del criterio elegido para el dato faltante más que del sistema.

6. **La pregunta 3 está mal definida para lo que mide.** «Una cadena contiene a la otra» mezcla casos benignos (I63: «node» frente a «nodejs», mismo producto; «Server Core installation») con casos dañinos (complementos de Jenkins). Conviene registrar por separado la coincidencia de fabricante (p. ej. «Jenkins Project» frente a «jenkins») y la de producto, y clasificar el texto sobrante (calificador de instalación, edición, componente distinto).

7. **Solo se mide precisión.** El diseño sortea pares que el sistema generó; no puede ver los pares que la vía debería haber generado y no generó. Cualquier afirmación sobre la cobertura de la vía de inferencia necesita otro diseño.

8. **Casos que no son independientes.** El mismo CVE aparece varias veces (CVE-2026-69631 en I28, I41 e I54), y muchos CVE de Microsoft del mismo mes tienen bloques `affected` idénticos. El tamaño efectivo de la muestra es menor que 65 para estimar intervalos. Además, el caso (CVE + producto) no es la unidad de alerta (CVE + activo); ver la nota de ponderación.

9. **Copia del registro al cierre frente a la ingesta.** Los nombres coinciden en los 65 casos, pero los rangos pueden haberse corregido después de la ingesta. Si el sistema hubiera filtrado por versión al ingerir, la comparación correcta sería con el registro de ese momento. Como no filtra, esto no cambia los veredictos, pero conviene dejarlo dicho.

10. **Riesgo de contaminación de los insumos.** En la carpeta de la muestra hay un archivo `errores_conocidos.csv`. Si el revisor lo abre, deja de ser independiente. No lo abrí. Convendría moverlo fuera de la carpeta de insumos en futuras revisiones, o excluirlo de forma explícita en el encargo, como se hizo con la carpeta de la propuesta previa.

11. **Un solo revisor y sin acuerdo entre jueces.** Este juicio lo hizo un único modelo de lenguaje. Para los 22 casos que no son Windows, que concentran toda la variación, convendría un segundo juicio humano y calcular el acuerdo entre ambos.
