# Bloque 6 — Respuesta a la revisión independiente de los 65 casos de inferencia

**Fecha:** 4 de octubre de 2026 · **Informe revisado:** `2026-10-04_bloque6_revision_independiente_inferencia.md`
**Veredicto final:** `data/cleaned/bloque6_revision_inferencia/propuesta.csv` (generado por `scripts/bloque6_prerevision_inferencia.py`)

## Contraste caso por caso

La propuesta previa (hecha antes de lanzar al revisor, sin pasársela) y el revisor coinciden en 61 de 65 casos.

| Caso | Propuesta previa | Revisor | Final | Por qué |
|---|---|---|---|---|
| I08 Confluence | dudoso | dudoso, recomienda correcto | **correcto** | La falla existe desde 7.4.0; la 8.2 quedó sin soporte y sin corrección. Que el fabricante no la evalúe no la hace segura |
| I63 Node.js | error de versión | dudoso, recomienda correcto | **correcto** | La propuesta previa se equivocó: el registro nombra solo las ramas con soporte (22, 24 y 26), no excluye la 18. Mismo criterio que I08 |
| I64, I65 OpenVPN | dudoso | dudoso, recomienda error de plataforma | **error de plataforma** | La falla exige Windows y el inventario no lo confirma. Mismo tratamiento que los 82 pares solo por plataforma de la vía formal |

**Resultado:** 58 correctos, 7 errores (3 de versión, 2 de complemento, 2 de plataforma). Coincide con la recomendación del revisor.

## Observaciones del revisor que se aceptan (van a pendientes)

1. Informar la precisión separando Windows del resto: los 43 casos Windows son coincidencias exactas de nombre y no ponen a prueba la inferencia. La ponderación por estrato ya permite esa separación.
2. Las versiones del inventario son viejas o sin soporte, y caen bajo casi cualquier límite «menor que X»: la precisión de versión depende del inventario. Limitación a declarar.
3. «Correcto» significa producto y versión correctos, no activo expuesto: no se evalúan roles ni configuración.
4. Criterio de lectura de rangos fijado y declarado: rango leído con la descripción; versiones sin soporte no evaluadas cuentan como afectadas si la falla es anterior.
5. La validación mide precisión; la cobertura se midió aparte (bloque 4B).

## Observaciones que no cambian nada

- Mismo CVE en I28, I41 e I54: es el diseño (la unidad es vulnerabilidad más producto, y son tres productos distintos).
- La unidad del caso no es la unidad de alerta: ya resuelto, la tasa se informa por caso y por par.
- Riesgo de contaminación por `errores_conocidos.csv` en la carpeta de insumos: el revisor no lo abrió. En futuras revisiones se excluye del encargo.

## Cambio del 11 de octubre de 2026 (bloque 11)

**I64 e I65 (OpenVPN) pasan de error de plataforma a correctos**, por decisión del autor. La falla exige que el servidor corra sobre Windows y el inventario no registra el sistema de `srv-vpn-gw`. Es la misma situación que Exim (I12), cuya falla exige una opción de configuración que el inventario tampoco registra y que se juzgó correcto: en los dos casos el producto y la versión coinciden y falta un dato del entorno. El criterio evalúa producto y versión, no exposición.

La decisión del 04/10 los había asimilado a los pares solo por plataforma de la vía formal. La analogía no se sostiene: en esos pares el producto del activo (macOS) no es el afectado sino el sistema sobre el que corre otro programa; en OpenVPN el producto del activo es el afectado. El cambio se aparta de la recomendación del revisor, que los juzgaba error.

**Resultado nuevo:** 60 correctos, 5 errores (3 de versión, 2 de complemento). Las reglas de lectura pasan de cuatro a tres: la de plataforma y la de configuración se unen en una sola («condición del entorno no registrada: no se evalúa»). Regenerado `data/cleaned/bloque6_revision_inferencia/propuesta.csv`; solo cambian las filas I64 e I65. Registro: decisión 19 del plan de cierre.
