# Bloque 11 — Respuesta a la revisión independiente de la tasa de error de la inferencia

**Fecha:** 11 de octubre de 2026 · **Informe revisado:** `2026-10-11_bloque11_revision_tasa_error.md`

## Qué se aceptó

| Hallazgo | Respuesta |
|---|---|
| El intervalo de Wilson sobre el tamaño efectivo de Kish descansa en un supuesto que no se cumple (el error depende del peso) | Se acepta. El script pasa a Korn-Graubard (varianza del diseño estratificado con corrección por población finita, estratos censados sin varianza, Clopper-Pearson sobre el tamaño efectivo topeado). Se reprodujeron las cifras del revisor exactamente. Wilson-Kish queda como contraste en la salida |
| El comentario del script decía «ocho de doce productos sin error»; eran siete | Se acepta y se corrigió. Tras el cambio de OpenVPN del mismo día, son ocho, y así dice ahora |
| La separación Windows Server / resto no estaba prevista en el sorteo | Se acepta. El texto de 5.2.2 la declara como lectura descriptiva decidida al revisar la muestra |
| La tasa del resto depende de pocos juicios | Se acepta. El texto dice que un error de Jenkins menos baja la tasa del grupo unos cinco puntos |
| Orden inestable de filas en la salida por producto | Se corrigió (desempate por nombre) |

## Qué no cambió

- Columnas «revisados» y «errores» en las filas por par: cuentan casos, no pares. Se deja; el texto de la tesis no las usa como conteo de pares.
- Listas escritas a mano (productos Windows Server, etiqueta del firewall) y controles contra cifras escritas: correctas hoy, se dejan.

## Cifras posteriores al informe

El mismo día, el autor reclasificó I64 e I65 (OpenVPN) como correctos (decisión 19 del plan; ver la adenda de `2026-10-04_bloque6_respuesta_a_la_revision.md`). Las cifras del informe del revisor corresponden a la clasificación anterior. Las vigentes: total 3,2 % por caso (0,5 a 10,3), 1,9 % por par (0,1 a 8,3); resto 19,4 % (7,2 a 38,3) y 11,6 % (2,8 a 29,0); Windows Server sin cambios. Fuente: `data/cleaned/bloque11_precision_inferencia/tasa_error.csv`.
