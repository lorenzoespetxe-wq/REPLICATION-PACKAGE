# Revisión independiente del cambio de criterio de OpenVPN (bloque 11)

**Fecha:** 11 de octubre de 2026
**Objeto:** el cambio por el que los dos casos de OpenVPN de la muestra de la vía de inferencia (I64 e I65, CVE-2026-81830 y CVE-2026-84256, activo `srv-vpn-gw`) pasan de error de plataforma a correctos, y las reglas de lectura pasan de cuatro a tres.
**Alcance:** si el cambio quedó aplicado en todo lo vigente (suficiencia) y si las cifras y oraciones editadas son correctas. No se juzga si la reclasificación es acertada en el fondo.

## Conclusión

El cambio está completo y las cifras son correctas. No encontré nada vigente que siga expresando el criterio viejo o las cifras viejas. Dejo dos observaciones menores de redacción, las dos opcionales, y aclaro en cada una por qué no son defectos del cambio.

## Qué verifiqué y cómo

1. **El script de la prerevisión y su salida.** Ejecuté `scripts/bloque6_prerevision_inferencia.py` con la salida desviada a una carpeta temporal. Da 60 correctos y 5 errores, y el archivo que genera es idéntico byte a byte a `data/cleaned/bloque6_revision_inferencia/propuesta.csv`. Los cinco errores son I09 (Confluence, versión), I15 e I16 (GitLab, versión) e I18 e I19 (Jenkins, complemento). I64 e I65 figuran como correctos, sin tipo de error y con un motivo que nombra el sistema no registrado. El comentario del encabezado describe la regla unificada y aclara que no toca el error de plataforma de la vía formal.

2. **El script de la tasa y sus salidas.** Ejecuté `scripts/bloque11_precision_inferencia.py` del mismo modo. `tasa_error.csv` y `error_por_producto.csv` salen idénticos a los del repositorio. Rehice a mano los errores ponderados: Confluence 1, GitLab 2 × 11 = 22, Jenkins 2 × 17,67 = 35,33, que suman 58,33, más los 7 del firewall, 65,33. Sobre 2.025 casos da 3,23 %; sobre 3.424 pares, 1,91 %; sobre los 337 casos fuera de Windows Server, 19,39 %; sobre sus 562 pares, 11,63 %. El comentario del script dice que ocho de los doce productos no tuvieron error. Ahora es cierto: los tres Windows Server, macOS, OpenVPN, Elasticsearch, Exim y Node.js.

3. **Secciones 5.2, 5.2.1 y 5.2.2 de `paper/main.md`, contra `tasa_error.csv`.**
   - Tabla de tasas: 3,2 % (0,5 a 10,3) y 1,9 % (0,1 a 8,3); resto 19,4 % (7,2 a 38,3) y 11,6 % (2,8 a 29,0); Windows Server 0,0 % (0,0 a 8,2). Todo coincide con el redondeo de la salida.
   - «12 casos con error» en el resto y en el total: coincide (5 de la muestra y 7 del firewall).
   - «casi uno de cada cinco» (19,4 %) y «uno de cada catorce» en el extremo favorable (7,16 %, que es 1 de 13,97): correctos.
   - «Un error de Jenkins menos baja unos cinco puntos»: 17,67 / 337 = 5,2 puntos. Correcto, y siguen siendo dos los errores de Jenkins.
   - «Coincidió en 61» y «cuatro diferencias» (Confluence, Node.js y los dos OpenVPN): coincide con la respuesta del 04/10.
   - La tabla de reglas tiene tres filas. La nota dice que la primera y la tercera resolvieron las diferencias y que en OpenVPN la decisión se aparta de la revisión independiente. Coincide con la tabla y con el registro.
   - El párrafo de criterio al abrir la 5.2 («no examina si el activo […] corre sobre el sistema operativo […]») es coherente con la regla nueva.
   - «Las dos últimas reglas» del párrafo posterior a la tabla son la de Windows y la de condición del entorno, las dos que aceptan el par. Es coherente con la tabla (ver la observación 1).

4. **Búsqueda en todo el repositorio** (tesis, scripts, salidas en `data/cleaned/` y `paper/tables/`, `quality_reports/`, `Refactored Context/`) de: 58 correctos, «58 y 7», 7 errores, 14 errores, cuatro reglas, «error de plataforma» o «errores de plataforma», OpenVPN, I64 e I65, los dos CVE, `srv-vpn-gw`, las tasas viejas (3,6 %, 2,1 %, 21,8 %, 13,1 %, 8,7 a 40,9) y «rechaza el par». Resultado:
   - **Tesis (`paper/main.md`).** «Plataforma» aparece solo en dos sentidos: el identificador de plataforma del inventario y la correlación solo por plataforma de la vía formal (1.7, 5.1, Anexo A). Ninguna mención la presenta como error de la inferencia. OpenVPN aparece en la tabla del inventario (4.3), en la 5.1.4 y en la 5.2.1. Ninguna lo trata como error.
   - **Mapa de trazabilidad.** Las filas de validación de la inferencia, de revisión independiente y de tasa están actualizadas, anotadas «corregido el 11/10» y apuntan a las salidas correctas. Las filas de plataforma que quedan son de la vía formal.
   - **Pendientes.** La fila del resultado del bloque 6 tiene el criterio viejo tachado y el nuevo escrito. La fila del inventario explica el efecto nuevo: «ya no produce error». La fila de costo de la ceguera de versión dice 3 de 65, cifra que no cambió.
   - **Plan de cierre.** La decisión 19 está registrada y la fila del bloque 6 está anotada.
   - **`ESTADO_DEL_PROYECTO.md`.** La actualización del 04/10 tiene la anotación del 11/10.
   - **Respuestas a las revisiones.** La adenda del 04/10 y la respuesta del 11/10 registran el cambio y las cifras vigentes.
   - **Salidas de datos.** `paper/tables/cifras_capitulo5.csv` y las tablas t5 no contienen cifras de precisión. `data/cleaned/bloque5_muestra_validacion/` no clasifica errores: solo sortea, así que no se ve afectado.
   - **Scripts.** Todas las demás menciones de «plataforma» en `scripts/` (bloques 1, 2, 4B, 5, 7, 8, 9 y 10) se refieren a la vía formal o a la marca `vulnerable` de la NVD.

## Lo que no marqué y por qué

- **Registros históricos con las cifras viejas.** Siguen las cifras viejas en la tabla y el resultado del 04/10 de `2026-10-04_bloque6_respuesta_a_la_revision.md` (el cambio se registra en la adenda del mismo archivo), en los informes de los revisores del 04/10 y del 11/10 (14 errores, 3,62 %, 8,69 a 40,92 %, «58 y 7»), en `SESSION_REPORT.md`, en los borradores y en los documentos de `Refactored Context/` distintos de `ESTADO_DEL_PROYECTO.md`. Todo esto es historia, y los documentos vigentes registran el cambio.
- **Referencias al error de plataforma de la vía formal** (Chrome sobre macOS, 82 + 20 pares, bloque 7): son correctas y no se tocan.
- **Plan de cierre, líneas 176 y 250**, la descripción original de los bloques. Hablan de «las cuatro clases de error del criterio» (producto derivado, complemento, plataforma y ceguera de versión). Esa lista abarca las dos vías, y la plataforma sigue siendo una clase de error de la vía formal, así que no contradice el criterio nuevo. Además es texto de planificación del 29/09.
- **`paper/output/tesis.pdf` y `tesis.docx`.** Son del 3 y el 5 de octubre, anteriores a toda la sección 5.2. Es una compilación vieja, no un efecto de este cambio.

## Observaciones menores (cosméticas, opcionales)

1. **`paper/main.md`, línea 1152, primera oración.** Dice: «Las dos últimas reglas aceptan el par cuando el producto y la versión coinciden y lo que falta es un dato del entorno…». Para la regla de Windows esto es impreciso: ahí la versión no coincide ni deja de coincidir, porque el inventario no la registra («no verificable» en `propuesta.csv`). La oración siguiente del mismo párrafo lo aclara («donde la precisión que se informa es la del producto y no la de la versión»), así que el párrafo en conjunto no queda falso. No sé si esta oración se reescribió con el cambio o ya estaba así, porque la sección 5.2 no tiene versión anterior en git. *Clasificación: cosmético.* Arreglo mínimo, si se quiere: «aceptan el par cuando el producto coincide, la versión no lo contradice y lo que falta es un dato que el inventario no registra».

2. **Plan de cierre, línea 597 (fila del bloque 6).** Termina con «Criterios de rango, versión ausente y plataforma fijados y escritos en el script». La fila ya tiene la anotación del 11/10 con las cifras nuevas, pero esa última oración sigue nombrando un criterio «de plataforma» que ya no existe como tal, porque ahora es «condición del entorno». Es un registro de lo hecho el 04/10, de modo que también puede leerse como historia; no estoy seguro de cuál de las dos lecturas corresponde. *Clasificación: cosmético; contradice levemente un documento de trabajo vigente si se lo lee como estado actual.* Arreglo mínimo: agregar «(plataforma y configuración unidas en “condición del entorno” el 11/10)».

## Sobre cómo se formuló el encargo

- El encargo declara de antemano qué no está afectado (la vía formal) y qué documentos son historia. Eso reduce el riesgo de recomendar cambios de más, pero también podría ocultar algo. Comprobé por mi cuenta que todas las menciones de plataforma que quedan como error son de la vía formal, y que cada documento histórico tiene un documento vigente que registra el cambio. La exclusión resultó correcta.
- El encargo pide verificar si el cambio quedó aplicado, no si es acertado. Por eso esta revisión no evalúa si tratar «falla solo sobre Windows, sistema no registrado» igual que «opción de configuración no registrada» es el criterio correcto. Esa decisión, que se aparta de la recomendación de la revisión independiente del 04/10, queda sin una segunda mirada independiente sobre el fondo. Las cifras dependen de ella: con OpenVPN como error, la tasa del resto vuelve a cerca del 21,8 %.
