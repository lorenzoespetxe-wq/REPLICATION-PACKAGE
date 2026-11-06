# Instrucciones que recibió cada modelo en la validación

Este archivo reproduce, sin cambios, las instrucciones con que se lanzaron las revisiones independientes de la validación (sección 5.2 y Anexo E de la tesis). Se extrajeron del registro de las sesiones de trabajo. Las rutas que mencionan son las del equipo del autor; en el paquete, los mismos archivos están bajo `replication/analisis/`.

El juicio previo de cada vía no tuvo una instrucción única: el modelo propuso un veredicto por caso durante la sesión de trabajo, a pedido del autor, y el autor lo aprobó o lo corrigió caso por caso. El resultado está en `data/cleaned/bloque6_revision_inferencia/propuesta.csv` (vía de inferencia) y en `data/cleaned/bloque7_revision_formal/` (vía formal).

## 1. Revisión independiente de la vía de inferencia (4 de octubre de 2026)

Modelo: Claude Opus 5.5. Informe: `quality_reports/reviews/2026-10-04_bloque6_revision_independiente_inferencia.md`.

````text
Sos un revisor independiente para una tesis de ciberseguridad (UTN, en español). Trabajás en el repositorio `C:\Users\loren\Desktop\Agentes de Claude para Tesis\clo-author-main\clo-author-main`. Solo lectura, salvo el informe final que se te pide escribir.

## Contexto mínimo
Un sistema automatizado (flujo n8n) cruzó vulnerabilidades publicadas (CVE) contra un inventario de 30 activos. Una de sus vías de correlación, la "vía de inferencia", compara el fabricante y el producto que el registro CVE declara en texto libre contra el fabricante y producto del identificador CPE de cada activo, normalizando a minúsculas alfanuméricas y aceptando que una cadena contenga a la otra. No mira versiones. Se sortearon 65 casos de esa vía para validarlos a mano. Cada caso es una vulnerabilidad más un producto del inventario.

## Insumos
- Casos: `data/cleaned/bloque5_muestra_validacion/planilla_revision.csv`, filas con `via == inferencia` (ids I01 a I65). La columna `nombres_leidos_por_el_artefacto` es lo que el sistema leyó al ingerir.
- Inventario: `data/raw/activos_inventario.csv` (hostname y CPE; la versión es el sexto campo del CPE; `-` significa que no se registró).
- Registros CVE tal como los publicó la CNA, copia local al cierre: `data/raw/cvelistv5_cierre/cves/<año>/<NNxxx>/CVE-....json` (bloque `containers.cna.affected`, `descriptions`, `references`).
- Podés usar la web para consultar avisos de fabricantes si el registro no alcanza.

## Qué hacer
Para CADA uno de los 65 casos, juzgá por tu cuenta y anotá:
1. ¿El producto del inventario figura como afectado en el aviso o registro del fabricante? (sí / no)
2. ¿La versión del inventario cae en el rango declarado afectado? (sí / no / no verificable / dudoso)
3. ¿La coincidencia de nombres fue completa (mismo producto) o parcial (una cadena contiene a la otra, p. ej. un complemento o un producto derivado)?
4. Veredicto: ¿el par es correcto, es decir, la vulnerabilidad afecta al activo tal como el inventario lo describe? (correcto / error / dudoso), con tipo de error si corresponde (versión, complemento, producto derivado, plataforma, otro) y el motivo en una oración.

Para los dudosos, decí qué criterio aplicarías y por qué. Decidí vos qué hacer con los casos donde el inventario no tiene el dato necesario (versión ausente, sistema operativo no registrado) y declarás el criterio una vez.

Además, denunciá cualquier sesgo o problema que veas en este encargo o en el diseño de la validación (cómo se definieron las preguntas, qué no permiten ver, si los insumos alcanzan). No te limites a responder lo que se pregunta.

No te paso la propuesta previa de veredictos a propósito: tu juicio tiene que ser independiente. No busques archivos en `data/cleaned/bloque6_revision_inferencia/`.

## Salida
Escribí el informe en español en `quality_reports/reviews/2026-10-04_bloque6_revision_independiente_inferencia.md`, con:
- una tabla de los 65 casos (id, CVE, producto, las cuatro respuestas, motivo breve),
- los totales (correctos, errores por tipo, dudosos),
- los criterios que aplicaste para los casos sin dato,
- la sección de sesgos y problemas del encargo.
Devolveme al final un resumen de 10 líneas con los totales, la lista de ids que juzgaste error o dudoso, y los criterios.
````

## 2. Revisión independiente de la vía formal (4 de octubre de 2026)

Modelo: Claude Opus 5.5. Informe: `quality_reports/reviews/2026-10-04_bloque7_revision_independiente_formal.md`.

````text
Sos un revisor independiente para una tesis de ciberseguridad (UTN, en español). Trabajás en el repositorio `C:\Users\loren\Desktop\Agentes de Claude para Tesis\clo-author-main\clo-author-main`. Solo lectura, salvo el informe final que se te pide escribir.

## Contexto mínimo
Un sistema automatizado (flujo n8n) cruzó vulnerabilidades publicadas (CVE) contra un inventario de 30 activos. Una de sus vías de correlación, la "vía formal", compara el fabricante y el producto de los identificadores CPE que el NIST publica en el bloque de configuraciones de la NVD contra el CPE de cada activo. No evalúa rangos de versión ni distingue entre producto vulnerable y plataforma. Se revisan todas (censo) las vulnerabilidades cuyos pares persistidos por esa vía quedan por validar: 60 vulnerabilidades. Cada una puede abarcar varios activos.

## Insumos
- Casos: `data/cleaned/bloque5_muestra_validacion/planilla_revision.csv`, filas con `via == formal` (ids F01 a F60). Columnas `producto_inventario` y `activos` indican contra qué productos y activos correlacionó.
- Inventario: `data/raw/activos_inventario.csv` (hostname y CPE; la versión es el sexto campo del CPE; `-` significa que no se registró).
- Registros CVE tal como los publicó la CNA, copia local al cierre: `data/raw/cvelistv5_cierre/cves/<año>/<NNxxx>/CVE-....json`. Puede que algunos no estén; en ese caso usá la web (avisos del fabricante, p. ej. https://msrc.microsoft.com/update-guide/vulnerability/<CVE>, o la NVD).
- Foto de cierre de la NVD: `data/raw/nvd_reconsulta/configs_vulnerable_20261003.csv`.

No abras nada dentro de `data/cleaned/bloque6_revision_inferencia/`, `data/cleaned/bloque7_*`, ni `data/cleaned/bloque5_muestra_validacion/errores_conocidos.csv`, ni informes previos en `quality_reports/`: tu juicio tiene que ser independiente.

## Qué hacer
Para CADA una de las 60 vulnerabilidades, y para cada producto del inventario con el que correlacionó, juzgá por tu cuenta:
1. ¿El producto del inventario figura como afectado en el aviso del fabricante? (sí / no / solo como plataforma)
2. ¿La versión del inventario cae en el rango afectado? (sí / no / no verificable / dudoso)
3. Veredicto por producto: correcto / error / dudoso, con tipo de error si corresponde (versión, plataforma, producto, otro) y el motivo en una oración.

Declará una vez los criterios que aplicás cuando el inventario no tiene el dato necesario. Denunciá también cualquier sesgo o problema que veas en este encargo o en el diseño de la validación; no te limites a lo que se pregunta.

## Salida
Escribí el informe en español en `quality_reports/reviews/2026-10-04_bloque7_revision_independiente_formal.md`, con una tabla (id, CVE, producto, las tres respuestas, motivo breve), totales por vulnerabilidad y por par (los pares salen de la columna `activos`), criterios y la sección de sesgos y problemas. Devolveme al final un resumen de 10 líneas con totales, ids que juzgaste error o dudoso, y criterios.
````

## 3. Tercera revisión de la vía de inferencia, a ciegas (21 de octubre de 2026)

Modelo: Claude Sonnet 5.5. Informe: `quality_reports/reviews/2026-10-21_revision_3/muestra_sonnet/revision.md`.

````text
Sos revisor independiente de una muestra de validación. Tenés que juzgar, caso por caso, si una correlación automática entre una vulnerabilidad y un activo de un inventario es correcta. Trabajás a ciegas: no existe para vos ningún juicio previo, y no debés buscarlo.

## Contexto mínimo

Un sistema automático vinculó vulnerabilidades (CVE) con activos de un inventario simulado comparando los nombres de fabricante y producto que declara el registro de la vulnerabilidad con los del inventario. La comparación normaliza los nombres y acepta como coincidencia que un nombre contenga al otro. No compara versiones. La muestra tiene 65 casos. Un caso es una vulnerabilidad y un producto del inventario; si varios activos comparten producto, forman un solo caso.

## Criterio de corrección

Una correlación es **correcta** cuando cumple dos condiciones:
1. El registro de la vulnerabilidad (o el aviso de seguridad del fabricante) declara afectado el producto del activo.
2. La versión que registra el inventario cae dentro del rango afectado.

El criterio evalúa producto y versión, no exposición: no examina si el activo usa la función afectada, corre sobre un sistema operativo determinado o tiene la configuración que la falla requiere, porque el inventario no registra esos datos.

Cada caso recibe uno de tres veredictos: **correcto**, **error** o **dudoso** (cuando los datos disponibles no alcanzan para decidir). Si es error, indicá su tipo con tus propias palabras. Cuando un caso sea ambiguo, fijá vos una regla de lectura, escribila, y aplicala igual a todos los casos parecidos.

## Insumos

Todo está en esta carpeta (ruta absoluta):
C:\Users\loren\Desktop\Agentes de Claude para Tesis\clo-author-main\clo-author-main\quality_reports\reviews\2026-10-21_revision_3\muestra_sonnet\entrada\

- `casos.csv`: los 65 casos. Columnas: id, cve_id, producto_inventario (fabricante:producto), activos, pares y nombres_leidos_por_el_artefacto (los pares fabricante/producto que el sistema leyó en el registro).
- `activos_inventario.csv`: el inventario, con el identificador CPE de cada activo. La versión está en el quinto campo del CPE (un `-` significa que el inventario no registra versión).
- `registros_cve/`: el registro JSON de cada vulnerabilidad tal como lo publica el programa CVE. Mirá en `containers.cna` los bloques `affected`, `descriptions` y `references`.

Podés buscar en internet los avisos de seguridad de los fabricantes cuando el registro no alcance para decidir.

## Restricciones

- Leé solamente los archivos de esa carpeta y lo que encuentres en internet. No abras ningún otro archivo del repositorio ni del equipo: hay juicios previos sobre estos mismos casos y verlos invalidaría la revisión.
- Juzgá los 65 casos. No te saltees ninguno, aunque varios sean parecidos.

## Entregables

Guardá dos archivos en
C:\Users\loren\Desktop\Agentes de Claude para Tesis\clo-author-main\clo-author-main\quality_reports\reviews\2026-10-21_revision_3\muestra_sonnet\

1. `revision.md`: tus reglas de lectura primero, y después una tabla con una fila por caso y estas columnas: id | CVE | producto (versión del inventario) | ¿el producto figura como afectado? | ¿la versión cae en el rango? (sí, no o no verificable) | coincidencia de nombres (completa o parcial) | veredicto (correcto, error o dudoso) | tipo de error | motivo breve. Al final, cualquier sesgo o problema que veas en el encargo.
2. `revision.csv`: la misma tabla, con columnas `id,cve_id,producto_afectado,version_en_rango,coincidencia,veredicto,tipo_error,motivo`, y el veredicto escrito exactamente como `correcto`, `error` o `dudoso`.

Como respuesta final, devolvé solo cuántos casos quedaron en cada veredicto y la lista de los que no son `correcto`.
````
