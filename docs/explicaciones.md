# Explicaciones — TPE WAF

Apuntes para **repasar y defender** el TP. Mientras implementamos las protecciones del [plan de trabajo](plan-de-trabajo.md) van quedando acá las explicaciones de los conceptos que aparecen, en lenguaje llano. La bitácora cuenta *qué hicimos*; este documento explica *por qué funciona*.

**Índice**

1. [ModSecurity, CRS y reglas](#1-modsecurity-crs-y-reglas)
2. [Cómo la imagen carga nuestras reglas](#2-cómo-la-imagen-carga-nuestras-reglas)
3. [ConfigMap](#3-configmap)
4. [Kustomize y el truco del hash](#4-kustomize-y-el-truco-del-hash)
5. [Volúmenes en el Deployment](#5-volúmenes-en-el-deployment)
6. [Flujo completo: cambiar una regla con el sistema corriendo](#6-flujo-completo-cambiar-una-regla-con-el-sistema-corriendo)
7. [Anatomía de una regla: la `10100` (3.1)](#7-anatomía-de-una-regla-la-10100-31)
8. [Query params: cuando NO escribimos regla (3.2)](#8-query-params-cuando-no-escribimos-regla-32)
9. [Body: buffering, parseo y `ARGS_POST` (3.3)](#9-body-buffering-parseo-y-args_post-33)
10. [Headers y cookie: scanner + SESSIONID (3.4)](#10-headers-y-cookie-scanner--sessionid-34)
11. [Estructura del request: 400 y 413 (3.5)](#11-estructura-del-request-400-y-413-35)
12. [Logging y auditoría: cómo se leen los logs](#12-logging-y-auditoría-cómo-se-leen-los-logs)

---

## 1. ModSecurity, CRS y reglas

**ModSecurity** es el motor de WAF que corre dentro de nuestro componente `waf`. Inspecciona el tráfico HTTP en **capa 7**: mira la URL, los query params, los headers, las cookies y el body de cada request, y decide si lo deja pasar, lo registra o lo bloquea. Por sí solo no sabe qué es "un ataque"; solo sabe **evaluar reglas** contra el request.

Las piezas:

- **ModSecurity (el motor).** Es un *módulo* enganchado a NGINX. NGINX recibe el request, ModSecurity lo inspecciona con las reglas, y si pasa, NGINX lo reenvía al backend (`ui.the-store`). La imagen `owasp/modsecurity-crs:nginx` trae los tres juntos: NGINX + ModSecurity v3 + CRS.
- **Las reglas.** Le dicen qué mirar y qué hacer. Vienen de dos lados:
  - **OWASP CRS** (Core Rule Set): paquete grande de reglas genéricas, mantenidas por la comunidad, que detectan SQLi, XSS, path traversal, scanners, etc. Son las familias `9xxxxx` (941 XSS, 942 SQLi…).
  - **Las nuestras** (`10000–19999`): específicas de The Store, que el CRS no puede conocer (ej. "bloquear `/utility` desde afuera").

**Tres conceptos de ModSecurity que usamos todo el tiempo:**

- **Fases (`phase`).** El request se evalúa por etapas: `phase:1` = headers y URL (antes de leer el body), `phase:2` = body. Una regla que solo necesita el path y la IP va en `phase:1` (más barata, bloquea antes); una que mira el body va en `phase:2`.

- **Modos (`SecRuleEngine`, nuestra variable `MODSEC_RULE_ENGINE`):**
  - `Off` → no inspecciona nada (ni genera audit log).
  - `DetectionOnly` → inspecciona y **loguea**, pero deja pasar. Sirve para medir falsos positivos sin romper nada.
  - `On` → inspecciona y **bloquea** (403, etc.).

- **Anomaly scoring.** El CRS no bloquea apenas matchea una regla: cada regla que salta **suma puntos**, y recién cuando se supera un umbral, una regla final (la **`949110`**) hace el bloqueo. Por eso en el log se ven dos: la que *detectó* y la que *bloqueó*. (Nuestras reglas propias, en cambio, usan `deny` directo: no suman puntaje, cortan al toque, porque no hay nada que dudar.)

En una frase: **ModSecurity = el motor que lee el HTTP y aplica reglas; el CRS + nuestras reglas = el "cerebro" que define qué es malicioso.**

---

## 2. Cómo la imagen carga nuestras reglas

La imagen `owasp/modsecurity-crs` **no podemos modificarla**, y no tiene un "archivo de reglas del usuario" mágico. Lo que tiene es un `setup.conf` (que arma al arrancar) con una línea fija:

```
Include /etc/modsecurity.d/owasp-crs/rules/*.conf
```

donde `owasp-crs` es un symlink a `/opt/owasp-crs`. O sea: **cualquier archivo `.conf` que dejemos en ese directorio de reglas se incluye automáticamente**. Ese es nuestro punto de inyección: montamos ahí nuestro `custom-rules.conf` (como `zzz-custom-rules.conf`, para que por orden alfabético cargue después del CRS).

> Descartamos el otro candidato, `modsecurity-override.conf`: el script de arranque le hace `touch`, y si lo montáramos read-only (como monta Kubernetes los ConfigMap) el `touch` falla y el contenedor no levanta. El directorio de reglas no tiene ese problema: nadie escribe sobre nuestro archivo.

Cómo llega el archivo hasta ese directorio dentro del contenedor → ver [ConfigMap](#3-configmap) y [Volúmenes](#5-volúmenes-en-el-deployment).

---

## 3. ConfigMap

Un **ConfigMap** es un objeto de Kubernetes para guardar **configuración en texto** (archivos de config, variables) **separada de la imagen** del contenedor. La imagen trae el *programa* (NGINX + ModSecurity); la *configuración* va aparte y se la inyectamos al contenedor cuando arranca.

Por dentro es un diccionario de `clave: valor`. El nuestro:

```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: waf-modsec-rules
data:
  custom-rules.conf: |        # la clave = nombre del archivo
    SecRule REQUEST_FILENAME ...   # el valor = todo el contenido del archivo
```

Se puede inyectar al pod de dos formas: como **variables de entorno** o como **archivos montados** (un volumen). Nosotros usamos la segunda.

**Para qué sirve la separación:** cambiar la config sin reconstruir la imagen; usar la misma imagen en distintos entornos; versionar la config en YAML, en el repo.

**Límites:** es para texto **no sensible** y tiene un tope de ~1 MB. Para datos sensibles (contraseñas, la clave privada de HTTPS del paso 11) se usa un **Secret**, que es el hermano del ConfigMap pensado para eso.

En el WAF tenemos dos: `waf-nginx` (el `realip.conf`) y `waf-modsec-rules` (nuestras reglas).

---

## 4. Kustomize y el truco del hash

**Kustomize** (viene integrado en `kubectl`) toma un conjunto de manifiestos y los **ensambla y transforma** antes de aplicarlos. El archivo `waf/kustomization.yaml` es la "receta". Cuando corrés `kubectl apply -k waf/`, el `-k` significa "leé el `kustomization.yaml`, generá el YAML final y aplicalo".

Tiene dos secciones que usamos:

- **`resources:`** → los manifiestos que se aplican **tal cual** (deployment, service, ingress, namespace).
- **`configMapGenerator:`** → genera ConfigMaps **a partir de archivos sueltos** (`realip.conf`, `custom-rules.conf`), en vez de escribir el ConfigMap a mano con el contenido embebido.

### El truco del hash (clave para entender el mecanismo)

Todo lo que está bajo `configMapGenerator` recibe, **por defecto**, un **sufijo-hash** en el nombre. El hash se calcula a partir del **contenido** del archivo:

```
name: waf-modsec-rules-ctcm9796t7     ← el nombre + hash del contenido
```

**Por qué importa:** un pod lee su config **al arrancar** y no la vuelve a mirar. Kubernetes reinicia un pod cuando cambia el **Deployment**, no cuando cambia un archivo suelto. Si el ConfigMap se llamara siempre `waf-modsec-rules` (nombre fijo) y editáramos su contenido, el Deployment seguiría diciendo lo mismo → Kubernetes no reiniciaría nada → WAF con reglas viejas.

Con el hash, **contenido distinto ⟹ nombre distinto**. Kustomize cambia el nombre del ConfigMap *y* reescribe la referencia en el Deployment, los dos a la vez. Así, editar el archivo cambia el texto del Deployment, y eso sí dispara el reinicio. (Ver el flujo completo en la [sección 6](#6-flujo-completo-cambiar-una-regla-con-el-sistema-corriendo).)

> No hay una línea que diga "poné un hash": es el comportamiento por defecto de `configMapGenerator`. Se podría apagar con `generatorOptions: { disableNameSuffixHash: true }`; como no la pusimos, el hash está activo. Un ConfigMap escrito a mano y puesto en `resources:` **no** tendría hash.

**Detalle que ya nos mordió:** el generador necesita `namespace: edge-security` para que Kustomize reescriba la referencia del Deployment (que está en ese namespace). Sin eso, genera el ConfigMap con hash pero el Deployment sigue pidiendo el nombre sin hash → pod en `ContainerCreating` con `configmap not found`.

---

## 5. Volúmenes en el Deployment

El contenedor corre una imagen que no podemos tocar, y nuestras reglas viven afuera (en un ConfigMap). Un **volumen** es el mecanismo para meter ese archivo **adentro del contenedor, en la ruta exacta** donde el WAF lo busca, sin reconstruir la imagen. Son dos secciones:

**1. `volumes:` — de dónde sale el contenido**

```yaml
volumes:
  - name: modsec-rules          # nombre interno del volumen
    configMap:
      name: waf-modsec-rules    # el ConfigMap que lo llena (Kustomize le pone el hash)
```

**2. `volumeMounts:` — dónde se enchufa dentro del contenedor**

```yaml
volumeMounts:
  - name: modsec-rules                                                   # ¿qué volumen? el de arriba
    mountPath: /etc/modsecurity.d/owasp-crs/rules/zzz-custom-rules.conf  # ¿en qué ruta?
    subPath: custom-rules.conf                                           # ¿qué archivo del volumen?
```

El `name` compartido une las dos secciones. La cadena completa:

```
ConfigMap waf-modsec-rules
    │ (volumes: configMap)
    ▼
volumen "modsec-rules"
    │ (volumeMounts: name)
    ▼
/etc/modsecurity.d/owasp-crs/rules/zzz-custom-rules.conf   ← dentro del contenedor
    │ (setup.conf hace Include .../rules/*.conf)
    ▼
ModSecurity lo carga
```

### El detalle de `subPath`

La `mountPath` apunta a **un archivo**, no a una carpeta, gracias a `subPath`.

- **Sin `subPath`**: Kubernetes monta el volumen como **directorio** y reemplazaría toda la carpeta `/etc/modsecurity.d/owasp-crs/rules/`, **tapando los ~30 archivos de reglas del CRS**. El WAF se quedaría sin CRS.
- **Con `subPath: custom-rules.conf`**: monta **solo ese archivo** dentro de la carpeta existente, al lado de los del CRS. Los demás quedan intactos.

Es el mismo patrón que usa `realip.conf`: inyectar **un único archivo** en una carpeta que ya tiene otras cosas.

> **Contra de `subPath`:** un archivo montado con `subPath` **no** se actualiza en vivo cuando cambia el ConfigMap (los montados como directorio sí). Para nosotros no es problema: cambiamos reglas vía el hash + reinicio (sección 6), no con recarga en caliente.

---

## 6. Flujo completo: cambiar una regla con el sistema corriendo

Supongamos que editamos la regla `10100` con el WAF ya atendiendo tráfico.

**1. Editás el archivo local** (`waf/modsec/custom-rules.conf`). Todavía no pasó nada en el clúster.

**2. Corrés `kubectl apply -k waf/`:**
- Kustomize calcula el hash del contenido nuevo → ConfigMap con **nombre nuevo** (ej. `waf-modsec-rules-AAAA` → `waf-modsec-rules-BBBB`).
- Reescribe la referencia del Deployment para que su volumen apunte a `-BBBB`.
- `kubectl` manda el YAML al API server, que lo persiste en **etcd**.

**3. En etcd quedan:**
- el ConfigMap viejo `-AAAA` (huérfano, ya nadie lo usa; inofensivo),
- el nuevo `-BBBB`,
- el Deployment `waf` **actualizado** (es el mismo objeto; lo que cambió adentro es el nombre del ConfigMap que monta).

**4. El Deployment cambió → Kubernetes hace un rolling update** (acá entra lo del paso 5 del plan):
- crea un **pod nuevo** que monta `-BBBB` → arranca leyendo la regla editada;
- el pod nuevo **no recibe tráfico** hasta pasar el `readinessProbe` (`tcpSocket:8080`). Si la regla tiene un error de sintaxis, NGINX no levanta → nunca pasa readiness → **el update se aborta y el pod viejo sigue sirviendo**. Config rota nunca llega a producción;
- cuando el nuevo está *ready*, recibe tráfico y al viejo le llega `SIGTERM` → `preStop: sleep 8` (sigue atendiendo mientras el Ingress lo saca de sus destinos) → recién ahí muere. Esto evita los 502.

**5. Resultado:** WAF corriendo con la regla nueva, sin downtime.

```
vim custom-rules.conf
      │
kubectl apply -k waf/
      │  Kustomize: hash nuevo → ConfigMap "…-BBBB" + reescribe el volumen del Deployment
      ▼
 API server → etcd  (Deployment actualizado)
      │  "el template del pod cambió" → rolling update
      ├─ POD NUEVO monta "…-BBBB", espera readinessProbe
      ├─ enruta tráfico al nuevo
      └─ SIGTERM al VIEJO → preStop sleep 8 → muere
      ▼
 WAF con la regla nueva, sin cortar el servicio
```

**La idea de fondo:** Kubernetes reacciona a cambios de **objetos** (el Deployment), no al contenido de un archivo dentro de un contenedor. El hash convierte "cambié un archivo" en "cambió el Deployment", que es lo único que dispara el reinicio.

> **Alternativas que descartamos:** *Reloader* (un controller que observa el ConfigMap y dispara el restart) y un *sidecar watcher* (que hace `nginx -s reload` en vivo). Las dos agregan un componente o riesgo. Para un WAF, donde las reglas cambian poco, el reinicio controlado es más simple y seguro (es atómico: o levanta con la config nueva, o se queda la vieja).

---

## 7. Anatomía de una regla: la `10100` (3.1)

Esta es la regla que cubre el punto 3.1 (control de acceso por path e IP). La pre-entrega pide *una regla personalizada* que inspeccione el path y responda 403 si la IP no está en la allowlist; esto es exactamente eso.

```apache
SecRule REQUEST_FILENAME "@rx ^/(?:utility|proxy|actuator|info|topology)(?:[/;]|$)" \
    "id:10100,phase:1,deny,status:403,log,\
    t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,\
    msg:'Endpoint interno accedido desde IP no permitida',chain"
    SecRule REMOTE_ADDR "!@ipMatch 10.244.0.0/16,127.0.0.1"
```

### La forma general

```
SecRule   VARIABLE      "OPERADOR"       "ACCIONES"
          ¿qué miro?    ¿qué condición?  ¿qué hago si matchea?
```

Nuestra regla tiene **dos `SecRule`** unidas por `chain` → es **una sola regla** (un `id`) con **dos condiciones**: el `deny` dispara solo si matchean **las dos**.

### Primera línea — la condición del path

- **`REQUEST_FILENAME`** → la variable: el **path de la URL sin el query string**. Para `GET /proxy/orders?x=1` vale `/proxy/orders`. (Usamos esta y no `REQUEST_URI` para que el `?...` no moleste.)
- **`@rx ^/(?:utility|proxy|actuator|info|topology)(?:[/;]|$)`** → el operador `@rx` = match contra esa regex:
  - `^/` → empieza con `/`.
  - `(?:utility|proxy|actuator|info|topology)` → seguido por una de esas 5 palabras (`(?:...)` agrupa sin capturar).
  - `(?:[/;]|$)` → y después viene `/`, `;` o el fin del string. Hace que matchee `/utility`, `/utility/panic`, `/utility;x`, **pero no** `/utilityzzz` ni `/catalog`. Evita falsos positivos con paths que empiezan parecido.

### El bloque de acciones

- **`id:10100`** → identificador único (rango propio `10000–19999`).
- **`phase:1`** → se evalúa con headers + URL, antes del body. Alcanza con path e IP.
- **`deny`** → acción disruptiva: cortar.
- **`status:403`** → código de respuesta.
- **`log`** → registrarlo en el audit log.
- **`t:none,t:urlDecodeUni,t:normalizePath,t:lowercase`** → **transformaciones** aplicadas al path *antes* de correr la regex (el orden importa):
  - `t:none` → borra transformaciones por defecto (empezamos de cero).
  - `t:urlDecodeUni` → decodifica `%xx`/`%uXXXX` → `/%75tility` ⇒ `/utility`.
  - `t:normalizePath` → colapsa `//` y resuelve `.` y `..` → `//utility` y `/catalog/../utility` ⇒ `/utility`.
  - `t:lowercase` → a minúsculas → `/Utility` ⇒ `/utility`.
  - **Por esto caen todos los bypass:** la regex ve el path ya normalizado, no el string crudo del atacante.
- **`msg:'...'`** → texto legible en el log.
- **`chain`** → "la regla sigue en el próximo `SecRule`"; el `deny` recién corre si matchean las dos condiciones.

### Segunda línea — la condición de la IP (encadenada)

- **`REMOTE_ADDR`** → la IP de origen. Por el paso 5, trae la IP **real** del cliente (tomada de `X-Real-IP` vía el módulo `realip`), no la del Ingress.
- **`@ipMatch 10.244.0.0/16,127.0.0.1`** → matchea si la IP está en la red de pods del clúster o loopback.
- **`!`** → **niega**: matchea cuando la IP **NO** está ahí → "viene de afuera".
- No lleva acciones propias: **hereda** `id`, `phase` y `deny` del comienzo de la cadena.

> **¿Por qué `REMOTE_ADDR` y no el header `X-Real-IP` directo?** Para evitar *fail-open*: si la regla mirara el header y llegara un request **sin** él, no matchearía y el request pasaría. `REMOTE_ADDR` siempre tiene un valor con el que comparar. El dato igual proviene de `X-Real-IP` (vía `realip`), como dice la pre-entrega.

### La lógica, en una línea

> **Bloqueá con 403 si** el path es interno (`utility/proxy/actuator/info/topology`, ya normalizado) **Y** la IP de origen **no** es del clúster.

Desde adentro (IP en `10.244.0.0/16`) → la 2ª condición es falsa → pasa (200). Desde afuera → las dos verdaderas → 403.

**Verificado en el clúster real** (modo `On`): los 5 paths internos y los bypass dan 403; `/`, `/catalog` dan 200; el mismo path sensible desde un pod interno da 200; y el audit log muestra `client_ip` real, `http_code: 403` y la regla `10100`.

### Referencia rápida: familias del CRS

| IDs | Detecta |
| :-- | :-- |
| 913xxx | scanners (User-Agent) |
| 920xxx | violaciones del protocolo HTTP |
| 930xxx | path traversal / LFI |
| 931xxx | RFI |
| 932xxx | command injection |
| 941xxx | XSS |
| 942xxx | SQLi |
| 949110 | **el bloqueo por puntaje** (anomaly scoring) |

Nuestras reglas: `10000–19999`. El CRS: `900000+`.

---

## 8. Query params: cuando NO escribimos regla (3.2)

La protección 3.2 (inyección SQLi/XSS en `GET /catalog?tag=...`) es el caso opuesto a la 3.1, y por eso es la más importante de entender bien.

### Por qué acá no hay regla propia

En 3.1 el endpoint (`/utility`, `/proxy`, …) es **nuestro**: el CRS no lo conoce, así que si no escribíamos la `10100` nadie lo protegía.

En 3.2 el ataque es **SQLi y XSS**, que son ataques genéricos y conocidos. De eso ya se encarga el **OWASP CRS** que viene en la imagen, con cientos de reglas hechas y mantenidas por OWASP. Escribir una regla propia de SQLi sería:

- **Redundante:** repetir algo que el CRS ya hace.
- **Peor:** nuestra regex casera cubriría muchos menos casos que las reglas del CRS (que usan *libinjection*, ver abajo).

Regla general del TP: **regla propia solo cuando el CRS no cubre el caso** (endpoints nuestros, lógica de negocio, IP). Para ataques estándar, se usa y se afina el CRS.

### Entonces, ¿dónde está declarada la protección?

En ningún archivo nuestro — y está bien. **Ya viene declarada dentro de la imagen.** La imagen `owasp/modsecurity-crs` no trae solo el motor: trae **todo el CRS ya escrito** en archivos `.conf`. Esos archivos *son* las reglas. En el pod conviven:

```
/etc/modsecurity.d/owasp-crs/rules/
├── REQUEST-941-APPLICATION-ATTACK-XSS.conf     ← OWASP (XSS)
├── REQUEST-942-APPLICATION-ATTACK-SQLI.conf    ← OWASP (SQLi)
├── REQUEST-949-BLOCKING-EVALUATION.conf        ← OWASP (bloqueo por score)
└── zzz-custom-rules.conf                        ← lo ÚNICO nuestro (la 10100)
```

La `942100` que vimos saltar está escrita en la línea 47 de `REQUEST-942-...-SQLI.conf`. No la escribimos nosotros: ya estaba.

**Por qué esas reglas están activas sin que hagamos nada:** es el mismo mecanismo de carga del punto 2. El `setup.conf` de la imagen hace `Include /etc/modsecurity.d/owasp-crs/rules/*.conf`, y ese `*.conf` carga **todos** los archivos de la carpeta en un solo barrido: los de OWASP (941/942/949…) **y** el nuestro. Por eso la protección de SQLi/XSS queda activa sola, solo por usar la imagen; lo nuestro (la `10100`) se suma al mismo barrido.

Dicho directo: **para SQLi/XSS no declaramos nada porque ya está declarado en los `.conf` del CRS.** La `10100` del paso 6 hizo falta solo porque `/utility`, `/proxy`, etc. son endpoints propios que OWASP no puede conocer.

### Qué hay que entender igual: cómo decide el CRS

Aunque no escribamos nada, en la defensa hay que saber **qué reglas saltaron y por qué**. Dos ideas:

**1. libinjection (no es regex).** Las reglas base `942100` (SQLi) y `941100` (XSS) no usan expresiones regulares: usan *libinjection*, que **tokeniza** el input como si fuera código SQL o HTML y decide si "parece" una inyección real. Es mucho más preciso que una regex y casi no da falsos positivos.

**2. Anomaly scoring (la regla que detecta ≠ la que bloquea).** Esto ya salió con la `10100`, pero acá se ve en acción:

- Cada regla que matchea **solo suma puntos** a un contador (una crítica suma +5).
- La que **bloquea** es la **`949110`**, al final de la fase, cuando el total pasa el umbral (default **5**).
- Por eso en el log de un mismo ataque aparecen **varias reglas** (las que sumaron) **y además** la `949110` (la que cortó).

### Lo que medimos en el clúster real

Con `MODSEC_RULE_ENGINE=On`, contra `localhost` (modo `On`):

| Request | Código | Reglas en el audit log |
| :-- | :-- | :-- |
| `?tag=1' OR '1'='1` (SQLi) | **403** | `942100` (+5) → `949110` (score 5) |
| `?tag=<script>alert(1)</script>` (XSS) | **403** | `941100`, `941110`, `941160`, `941390` → `949110` (score 20) |
| `?tag=tools` (legítimo) | **200** | — (no matchea nada) |

Detalles que conviene saber para la defensa:

- El **SQLi cortó con un solo hit** (`942100`, +5): alcanzó justo el umbral de 5. El **XSS acumuló 20** porque varias reglas lo detectaron a la vez (libinjection + el filtro del tag `<script>` + inyección HTML + método JS). Más señales → más puntaje, pero con una crítica ya alcanza.
- Los mensajes salen literales del log (`"SQL Injection Attack Detected via libinjection"`, `"XSS Filter - Category 1: Script Tag Vector"`, etc.). **No los asumimos: los leímos del audit log.**
- `/catalog` **no** lo bloquea nuestra `10100` porque no está en la lista de paths internos, así que la request llega hasta la inspección del CRS. Las dos protecciones conviven sin pisarse.

### El detalle fino: defensa en profundidad

Catalog hoy **no es vulnerable** (parametriza la consulta). Entonces, ¿para qué bloquear? Porque el WAF es una **capa extra**: si mañana una dependencia o un cambio de código reintroduce la inyección, el ataque igual muere en el WAF antes de tocar el servicio. Se protege el *patrón de ataque*, no un bug puntual.

> Para experimentar (no va en la entrega): subir el umbral (`ANOMALY_INBOUND`) y ver qué deja de cortar, o probar que el CRS también cubre path traversal (`930xxx`) y command injection (`932xxx`) con otros valores de `tag`.

---

## 9. Body: buffering, parseo y `ARGS_POST` (3.3)

La 3.3 es la misma idea que la 3.2 (el CRS hace el trabajo, no escribimos regla), pero el ataque ahora viaja en el **cuerpo** del `POST`, no en la URL. Eso agrega dos pasos que en la query no existían: **bufferizar** y **parsear**.

### Por qué el body es un punto de inspección aparte

Para mirar un query param, el WAF ya tiene la URL completa apenas llegan los headers (fase 1). El body es distinto:

- **Buffering:** el cuerpo puede venir en pedazos y el WAF necesita **guardarlo entero** antes de poder analizarlo. Esto pasa en **fase 2** (después de tener todo el request). Guardar el body cuesta memoria y tiempo → por eso hay un límite de tamaño (ver 3.5 / paso 10).
- **Parseo según `Content-Type`:** el body es texto crudo; el WAF lo interpreta según el header `Content-Type`:
  - `application/x-www-form-urlencoded` → cada campo del form.
  - `application/json` → cada campo del JSON.

### La idea central: todo termina en `ARGS_POST`

Después de parsear, **sin importar el formato original**, cada campo queda en la variable `ARGS_POST`:

| Enviado como | Variable que ve el CRS |
| :-- | :-- |
| form `firstName=...` | `ARGS:firstName` |
| JSON `{"name":"..."}` | `ARGS:json.name` |

Como las reglas 941/942 inspeccionan `ARGS` (que incluye `ARGS_POST`), **las mismas reglas cubren los dos formatos**. No hay una regla "para JSON" y otra "para forms": hay una sola, y el parser se encarga de normalizar. Ese es el concepto a transmitir en la demo.

### Lo que medimos en el clúster real (modo `On`)

| Request | Código | Variable que matcheó | Reglas (audit log) |
| :-- | :-- | :-- | :-- |
| `POST /checkout` (form), XSS en `firstName` | 403 | `ARGS:firstName` | 941100, 941110, 941160, 941390 → 949110 |
| `POST /catalog/products` (JSON), SQLi en `name` | 403 | `ARGS:json.name` | 942100 → 949110 |
| `POST /catalog/products` (JSON), XSS en `name` | 403 | `ARGS:json.name` | 941100, 941110, 941160, 941390 → 949110 |

Se ve el punto clave: el **mismo** XSS disparó las **mismas** reglas 941xxx en el form y en el JSON; lo único que cambió fue el nombre de la variable (`firstName` vs `json.name`). Los IDs y las variables salieron del audit log, no se asumieron.

### El intento de evasión: cambiar el `Content-Type`

Pregunta natural: ¿y si mando el JSON malicioso pero con `Content-Type: text/plain` para que el WAF no lo parsee como JSON? Lo probamos:

- `POST /catalog/products` con payload SQLi y `Content-Type: text/plain` → **403**, pero **no** por la regla de SQLi: cortó la **`920420` — "Request content type is not allowed by policy"**.

O sea, el truco no funciona. El CRS tiene una lista de `Content-Type` permitidos; si mandás uno fuera de esa lista, te bloquea de entrada. Quedan solo dos caminos y los dos están cubiertos:

1. Content-Type conocido (form/JSON) → lo parsea y lo inspecciona (941/942).
2. Content-Type no permitido → lo frena antes (920420).

No hay forma de "colar" el body sin inspección.

### Resumen

- La 3.3 **no agrega reglas propias**: reusa el CRS, igual que la 3.2.
- Lo nuevo es el *mecanismo*: buffering en fase 2 + parseo por `Content-Type` → todo a `ARGS_POST` → las mismas reglas 941/942.
- Bonus de defensa: el intento de evadir cambiando el `Content-Type` lo tapa la `920420`.

---

## 10. Headers y cookie: scanner + SESSIONID (3.4)

La 3.4 mezcla los dos mundos en un mismo paso: una parte la cubre el CRS (User-Agent) y la otra es **regla propia** (la cookie). Todo en **fase 1**, porque solo mira headers (no hace falta bufferizar el body).

### Parte CRS: User-Agent de scanners (familia 913)

Herramientas como `sqlmap`, `nikto` o `nmap` se delatan con un User-Agent característico. La familia **913xxx** del CRS los reconoce. Son reglas **críticas**: con un solo match ya suman +5 y la `949110` bloquea.

- Medido: `curl -A "sqlmap/1.7.2" http://localhost/` → **403**, por `913100` ("Found User-Agent associated with security scanner") → `949110`.
- **Hay que ser honestos en la defensa:** esto se evade cambiando el User-Agent (`-A "Mozilla/5.0"` pasa). Sirve contra escaneo automático, no contra alguien que sabe lo que hace. No es una defensa fuerte, es *ruido fuera*.

### Parte propia: formato de la cookie `SESSIONID`

Acá sí escribimos regla, por la misma razón que en 3.1: es **lógica nuestra que el CRS no conoce**.

El problema (verificado en el código): `SessionIDWebFilter.java` hace `sessionId = cookie.getValue()` **sin validar nada**. Si no viene cookie, crea una (un UUID v4). Pero si viene, acepta cualquier cosa. Entonces un atacante puede fijar `SESSIONID=victima-123`, o probar `1`, `2`, `3`…, y caer en la sesión de otro (IDOR) por el flujo normal, sin pasar por `/proxy`.

La defensa: exigir que la cookie **tenga formato UUID v4**. Si no lo cumple, 403.

```apache
SecRule REQUEST_COOKIES:SESSIONID "!@rx ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" \
    "id:10300,phase:1,deny,status:403,log,t:none,t:lowercase,msg:'SESSIONID con formato invalido (se espera UUID v4)'"

SecRule &REQUEST_COOKIES:SESSIONID "@gt 1" \
    "id:10301,phase:1,deny,status:403,log,msg:'Mas de una cookie SESSIONID'"
```

Dos detalles de la regla:

- **`REQUEST_COOKIES:SESSIONID`** = el *valor* de esa cookie. El `!@rx` (negado) dispara cuando el valor **no** matchea el patrón UUID v4. El patrón fija el `4` de la versión y el `[89ab]` del variant, que es lo que distingue un UUID v4 real.
- **`&REQUEST_COOKIES:SESSIONID`** (con `&`) = *cuántas* cookies con ese nombre vinieron. `@gt 1` → mandar dos `SESSIONID` para confundir el parseo (HTTP parameter pollution) también da 403.

**Clave:** si la cookie **no viene** (primera visita), `@rx` no tiene qué evaluar y la regla no dispara → la UI crea una nueva. Justo lo que queremos: no rompemos al usuario nuevo.

**Honestidad, otra vez:** esto frena IDs truchos o adivinados, **no** el robo de un UUID válido (si te roban una sesión real, el formato es correcto).

### Lo que medimos en el clúster real (modo `On`)

| Request | Código | Regla |
| :-- | :-- | :-- |
| `-A "sqlmap/1.7.2"` | 403 | `913100` → `949110` |
| `-b "SESSIONID=victima-123"` a `/cart` | 403 | **`10300`** (deny directo) |
| sin cookie a `/cart` | 200 | — (la UI crea la cookie) |
| `-b "SESSIONID=<uuid v4 válido>"` a `/cart` | 200 | — |
| `-A "Mozilla/5.0"` | 200 | — |

### El concepto nuevo: `deny` directo vs anomaly scoring

Mirando el log se ve una diferencia entre las dos partes:

- El **scanner** lo bloquea la `949110` **por puntaje** (la 913100 solo suma +5). Es el mecanismo del CRS.
- La **cookie** la bloquea **nuestra `10300` directamente**: no suma puntos ni espera a la 949110, porque la acción es `deny`. Corta en el acto.

Por qué la diferencia: las reglas del CRS usan scoring para poder combinar muchas señales débiles y decidir con el total (menos falsos positivos). Nuestras reglas (`10100`, `10300`, `10301`) son decisiones binarias y claras ("este path/esta cookie no corresponde") → `deny` directo, sin scoring.

---

## 11. Estructura del request: 400 y 413 (3.5)

Las protecciones 3.1 a 3.4 son **modelo negativo**: buscan patrones de ataque conocidos (SQLi, XSS, scanners…). La 3.5 es **modelo positivo**: no busca un ataque, exige que el request **tenga la forma esperada**. Son propiedades de protocolo que achican la superficie de ataque. Dos controles:

1. **JSON bien formado** → si no parsea, `400`.
2. **Tamaño del body** → si se pasa del límite, `413`.

### Cómo decide ModSecurity (la variable `REQBODY_ERROR`)

Al procesar el body en **fase 2**, ModSecurity setea una variable `REQBODY_ERROR = 1` si algo salió mal, y pone el detalle en `REQBODY_ERROR_MSG`. Dos cosas disparan ese error:

- JSON mal formado → `REQBODY_ERROR_MSG = "JSON parsing error: ..."`.
- Body más grande que `SecRequestBodyNoFilesLimit` → `REQBODY_ERROR_MSG = "Request body excluding files is bigger than the maximum expected."`.

### El problema con la config base

La imagen trae una regla base, la **`200002`**, que hace:

```apache
SecRule REQBODY_ERROR "!@eq 0" "id:200002,phase:2,deny,status:400,..."
```

O sea, **cualquier** `REQBODY_ERROR` → `400`. Lo comprobamos: un body de 500 KB daba **400**, no 413. La consigna pide `413` para "body demasiado grande", así que la config base **no alcanza**: mete "JSON roto" y "body grande" en la misma bolsa.

### Lo que hicimos: partir la 200002 en dos

Reemplazamos la regla base por dos propias, distinguiendo según el mensaje de error:

```apache
SecRuleRemoveById 200002

# Body demasiado grande -> 413
SecRule REQBODY_ERROR "!@eq 0" \
    "id:10400,phase:2,deny,status:413,log,t:none,msg:'...',chain"
    SecRule REQBODY_ERROR_MSG "@rx bigger than the maximum"

# Cualquier otro error de parseo (JSON roto, etc.) -> 400
SecRule REQBODY_ERROR "!@eq 0" \
    "id:10401,phase:2,deny,status:400,log,t:none,msg:'...'"
```

- **`SecRuleRemoveById 200002`**: desactiva la regla base. Esto funciona porque nuestro archivo (`zzz-custom-rules.conf`) se carga **después** de `modsecurity.conf` (donde vive la 200002), así que la puede quitar.
- **`10400`** (chain): dispara solo si hay error **y** el mensaje contiene "bigger than the maximum" → `413`. Es el caso "body grande".
- **`10401`**: si hay error pero no es por tamaño (ej: JSON roto) → `400`. Como la `10400` ya cortó el caso de tamaño con su `deny`, acá solo caen los demás.

### El límite y las dos capas de NGINX

El tamaño lo fija `SecRequestBodyNoFilesLimit` (para JSON y urlencoded). Lo declaramos **explícito** en `deployment.yaml`:

```yaml
- name: MODSEC_REQ_BODY_NOFILES_LIMIT
  value: "131072"            # 128 KB
- name: MODSEC_REQ_BODY_LIMIT_ACTION
  value: "Reject"
```

Detalle importante: hay **dos NGINX** en el camino y los dos tienen límite de body.

- El **WAF** corta a 128 KB → `413` por nuestra `10400`.
- El **Ingress** corta a 1 MB (su `client_max_body_size` default) → `413`, pero **antes** de llegar al WAF.

Por eso el payload de prueba es de 500 KB: pasa el Ingress (1 MB) pero no el WAF (128 KB), así el `413` lo da **el WAF**. La pregunta "si mando 2 MB, ¿quién devuelve el 413?" se contesta mirando el log: a 2 MB **no aparece nada en el audit log del WAF**, porque lo frenó el Ingress; a 500 KB sí aparece la `10400`.

### Lo que medimos en el clúster real (modo `On`)

| Request | Código | Quién / regla |
| :-- | :-- | :-- |
| JSON roto `{"name":"hola",}` | 400 | WAF, `10401` |
| body 500 KB | 413 | WAF, `10400` |
| body 2 MB | 413 | Ingress (no llega al WAF) |
| JSON válido y chico | 200 | — |

### Por qué 400/413 y no un simple "deny 403"

Los códigos importan: `400` le dice al cliente "tu request está mal formado", `413` dice "es demasiado grande". Son respuestas honestas de protocolo, no "te detecté un ataque" (`403`). Encaja con la idea de modelo positivo: no estamos acusando de ataque, estamos exigiendo forma válida.

---

## 12. Logging y auditoría: cómo se leen los logs

La pre-entrega promete *"logs estructurados de cada transacción analizada para proveer una posibilidad de auditoría"*. Esta sección explica qué se implementó, **cómo** se accede a esos logs y por qué el método elegido es correcto para la POC (y dónde está su límite).

### Qué genera el WAF

Desde el paso 5, el WAF está configurado (en `deployment.yaml`) para emitir un **audit log estructurado**:

```yaml
- name: MODSEC_AUDIT_ENGINE
  value: "On"          # registra TODAS las transacciones (no solo las bloqueadas)
- name: MODSEC_AUDIT_LOG_FORMAT
  value: "JSON"        # estructurado (una línea JSON por transacción)
- name: MODSEC_AUDIT_LOG
  value: "/dev/stdout" # no lo guarda en archivo: lo imprime por salida estándar
```

De ahí sale, por cada request, el `client_ip`, el `uri`, el `http_code` y los `ruleId` que saltaron. Es lo que leímos en cada paso para verificar las reglas.

### Cómo se leen: el stdout del contenedor

La clave es `MODSEC_AUDIT_LOG=/dev/stdout`: el WAF **no guarda** el log en un archivo dentro del pod, lo manda a **stdout**. En Kubernetes, el stdout de un contenedor lo captura el runtime y se lee con `kubectl logs`. Por eso el visor `scripts/waf-logs.sh` no entra al pod ni monta volúmenes: le pide el stdout a Kubernetes.

La cadena del visor es un pipe de 4 etapas:

```bash
kubectl logs -f deploy/waf -n edge-security \   # 1. trae el stdout del contenedor
  | grep '^{"transaction"' \                     # 2. filtra solo las líneas de audit JSON
  | jq -rc "$JQ_PROG" \                           # 3. parsea cada JSON -> fila legible
  | format                                        # 4. colorea e imprime alineado
```

El stdout viene **mezclado** (access log de nginx + error log + audit JSON de ModSecurity); el `grep '^{"transaction"'` se queda solo con las líneas de auditoría, que son objetos JSON que empiezan con `{"transaction"`.

### ¿Es seguro acceder así?

Hay que separar dos sentidos de "seguro":

**Acceso / permisos → sí.** `kubectl logs` es el mecanismo estándar y previsto de Kubernetes. Va contra el API server, autenticado y autorizado por **RBAC** con el `kubeconfig` del operador. Es **solo lectura**: no modifica el WAF, no entra al pod, no abre puertos. El script no agrega superficie de ataque.

- Matiz: el audit log contiene el **contenido de los requests** (headers, cookies, body). Quien pueda leer los logs ve esos datos — pero eso es inherente a *auditar* tráfico, no al método de acceso. En producción ese log es sensible y su lectura se restringe.

**Confiabilidad / durabilidad → no, y es la limitación real.** El stdout de un contenedor es **efímero**:
- Si el pod se reinicia o se reemplaza (los nuestros rotan en cada `kubectl apply`), los logs viejos **se pierden**.
- El kubelet rota los archivos de log por tamaño: aun sin reinicio, los más viejos se descartan.
- No es buscable históricamente.
- Con **2 réplicas** (paso 12), `kubectl logs deploy/waf` lee **un solo pod** → te perdés los eventos del otro.

Conclusión: `kubectl logs` es perfecto para **demostrar** la auditoría en vivo, pero no para **retenerla**.

### La alternativa "correcta" y por qué no se hace acá

El patrón productivo es no leer stdout a mano, sino enviarlo a un **agregador de logs** que lo persista y lo haga buscable: **EFK/ELK** (Fluent Bit → Elasticsearch → Kibana) o **Loki + Grafana**. Un colector junta el stdout de todos los pods y lo guarda central.

No se implementa en este TP por dos razones:
1. **Fuera de scope:** el tema es el WAF. "Gestión Centralizada de Logs (EFK)" y "Observabilidad (Loki/Grafana)" son **otros dos temas** del mismo TPE.
2. La pre-entrega promete *generar* logs estructurados con posibilidad de auditoría — y eso se cumple. No promete persistencia ni dashboard.

**Para la defensa oral:** decir que los logs se emiten estructurados (JSON) a stdout y que la retención/centralización (EFK, Loki) se deja fuera del scope por ser otro módulo de la arquitectura; acá se demuestra la **generación y el formato** de auditoría. Muestra que se conoce el límite de la decisión.

### Nota para el paso 12 (2 réplicas)

Cuando el WAF pase a 2 réplicas, `scripts/waf-logs.sh` debería leer de **todos** los pods (selector por label `-l app=waf --prefix`), no de `deploy/waf` (que resuelve a un solo pod). Pendiente para ese paso.
