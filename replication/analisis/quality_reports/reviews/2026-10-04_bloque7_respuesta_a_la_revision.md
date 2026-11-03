# Bloque 7 — Respuesta a la revisión independiente del censo formal

**Fecha:** 4 de octubre de 2026 · **Informe revisado:** `2026-10-04_bloque7_revision_independiente_formal.md`
**Veredicto final:** `data/cleaned/bloque7_revision_formal/propuesta.csv` (generado por `scripts/bloque7_prerevision_formal.py`)

## Contraste

Acuerdo total en los veredictos: 50 vulnerabilidades correctas y 10 con error de plataforma (F16 a F25, Chrome sobre las dos Mac). Por par: 357 correctos y 20 errores, sobre 377. Por producto: 159 y 10.

## Observaciones del revisor

| Observación | Respuesta |
|---|---|
| Posibles falsos negativos en F14, F15, F27 a F31 y F35: servidores que el aviso lista y la vía formal no registró | **Refutada con la base.** En las ocho, esos servidores tienen el par persistido por la vía de inferencia. El artefacto registra una sola vía por par, de modo que no hay omisión. Consulta: telemetria_vulnerabilidades por cve_id |
| La foto de cierre de la NVD no cubre F16 a F25 (publicadas el 25/08) | Correcta y ya conocida: son filas de estabilización, que se sumaron al censo justamente por no tener dato en esa foto. El revisor las verificó contra la API pública |
| El error de plataforma es un mecanismo, no una tasa | Se acepta. Se informa como mecanismo con su conteo: 82 pares en la campaña más 20 en estabilización, 102 de 459 pares formales |
| La tasa por pares depende de cuántas copias de cada producto tiene el inventario | Se acepta. Se informa por par, por producto y por vulnerabilidad |
| 79 pares correctos dependen de un rol que el inventario no registra (DHCP, NFS, Message Queuing, KDC) | Se acepta. Mismo criterio que el bloque 6: correcto significa producto y versión, no exposición. Se declara con el ejemplo del KDC |
| Validación casi circular en Microsoft: la NVD copia los datos del fabricante | Se acepta como limitación: en la vía formal la validación confirma la consistencia con la fuente, no aporta evidencia independiente sobre la versión |
| El encargo adelantaba los dos defectos de la vía | Correcta: sesgo del encargo. Los veredictos coinciden con una prerrevisión mecánica hecha en paralelo, así que no cambió el resultado. Para la revisión final se evita describir defectos en el contexto |
| La columna de nombres leídos está vacía en las filas formales | Correcto y deliberado: la vía formal no lee nombres |
