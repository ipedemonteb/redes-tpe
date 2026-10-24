# Plan de trabajo — TPE WAF

La idea es ir paso a paso: primero levantar todo, después meter el WAF y, a partir de ahí, sumar las protecciones de la pre-entrega **de a una**. En cada paso está el *qué* hacemos, el *por qué* y *cómo vemos que funciona*.

La guía es la [pre-entrega](pre-entrega.md): la consigna dice que hay que implementar *exactamente* lo que propusimos ahí, así que eso es lo que manda. El [análisis de endpoints](endpoints-security-analysis.md) sirve de referencia, pero lo que usemos de ahí lo chequeamos contra el código.

**Pasos**

0. [Conceptos base](#0-conceptos-base)
1. [Levantar el entorno](#1-levantar-el-entorno)
2. [Atacar la tienda sin WAF](#2-atacar-la-tienda-sin-waf)
3. [Crear el endpoint vulnerable](#3-crear-el-endpoint-vulnerable)
4. [Meter el WAF en el medio](#4-meter-el-waf-en-el-medio)
5. [Modos, logs e IP real](#5-modos-logs-e-ip-real)
6. [Protección: paths sensibles + IP (3.1)](#6-protección-paths-sensibles--ip-31)
7. [Protección: query params (3.2)](#7-protección-query-params-32)
8. [Protección: body (3.3)](#8-protección-body-33)
9. [Protección: headers y cookie (3.4)](#9-protección-headers-y-cookie-34)
10. [Protección: estructura del request (3.5)](#10-protección-estructura-del-request-35)
11. [HTTPS](#11-https)
12. [Cerrar los caminos alternativos](#12-cerrar-los-caminos-alternativos)
13. [Scripts de tests y demo](#13-scripts-de-tests-y-demo)
14. [How-to, PPT y ensayo](#14-how-to-ppt-y-ensayo)

---

## 0. Conceptos base

Antes de tocar nada, vale la pena tener claro este vocabulario.

**WAF.** Un firewall común decide por IP y puerto (capas 3 y 4). Un WAF trabaja en **capa 7**: entiende HTTP y puede mirar la URL, los parámetros, las cookies y el body. Por eso puede darse cuenta de que `?tag=1' OR '1'='1` es una inyección SQL, algo que un firewall de red no ve.

**Reverse proxy.** Un servidor que recibe la request del cliente y la reenvía a otro (el *backend*). Nuestro WAF es eso: un NGINX que recibe, analiza y, si todo está bien, reenvía a la UI.

**ModSecurity y el CRS.** ModSecurity es el **motor**: sabe ejecutar reglas, pero no trae ninguna que proteja algo. El **OWASP Core Rule Set (CRS)** es un conjunto enorme de reglas ya escritas para detectar ataques comunes. Necesitamos los dos.

**Cómo se ve una regla (SecLang):**
```apache
SecRule VARIABLE "OPERADOR" "ACCIONES"
SecRule ARGS:tag "@rx (?i)union\s+select" "id:10001,phase:2,deny,status:403,log,msg:'SQLi en tag'"
```
- **Variables:** qué mira la regla. Por ejemplo `REQUEST_FILENAME` (el path), `ARGS` (los parámetros), `REQUEST_HEADERS:User-Agent`, `REQUEST_COOKIES:SESSIONID`, `REMOTE_ADDR` (la IP).
- **Operadores:** cómo compara. `@rx` es una regex, `@ipMatch` compara IPs, `@detectSQLi` y `@detectXSS` usan libinjection. Con un `!` adelante se niegan.
- **Transformaciones** (`t:lowercase`, `t:urlDecodeUni`, ...): normalizan el valor *antes* de comparar, para que `%2e%2e%2f` y `../` se vean iguales.
- **Acciones:** qué hace si matchea. `deny`, `status:403`, `log`, `msg`, y `chain` para encadenarla con otra regla.

**Fases.** ModSecurity analiza cada request en etapas, y cada regla solo ve lo que hay disponible en su fase:
- **Fase 1:** headers, URI, cookies e IP. Es barata porque todavía no leyó el body.
- **Fase 2:** se suma el body ya parseado (formularios, JSON).
- **Fases 3 a 5:** la respuesta y el logging. Casi no las vamos a usar.

**Anomaly scoring.** El CRS no bloquea apenas una regla matchea: cada regla **suma puntos** (5 si es crítica, 4, 3 o 2 según la severidad). Al final, la regla **949110** compara el total con un umbral (5 por defecto) y, si lo pasa, devuelve 403. Así una señal débil sola no bloquea, pero varias juntas sí.

**Paranoia level (PL1 a PL4).** Define cuán estricto es el CRS. PL1 casi no da falsos positivos y es la que vamos a usar.

**Modelo negativo vs. positivo.** El negativo bloquea lo que *parece un ataque* (eso hace el CRS). El positivo solo deja pasar lo que *sabemos que es válido*, por ejemplo que la cookie tenga formato UUID. La pre-entrega usa los dos.

**Kubernetes en dos patadas:**
- **Pod:** contenedor(es) con una IP propia.
- **Deployment:** mantiene vivos N pods.
- **Service:** una IP fija que balancea hacia los pods. Por ejemplo `ui.the-store.svc.cluster.local`.
- **Ingress:** la regla de entrada ("localhost va al Service X"). El **Ingress Controller** (ingress-nginx) es el NGINX que la ejecuta.
- **Namespace:** agrupación lógica. Ojo: un Ingress solo puede apuntar a Services de **su mismo** namespace.
- **ConfigMap:** archivos de configuración que se montan en el pod. Ahí van a ir nuestras reglas.

---

## 1. Levantar el entorno

**Qué hacemos:** instalar las herramientas, levantar The Store tal como viene y entender por dónde pasa un request.

```bash
brew install kind kubectl jq        # + Docker Desktop con ~4 CPU / 8 GB de RAM
./local.sh create-cluster --skip-tests
```

**Kind** corre Kubernetes adentro de Docker: el "nodo" es un contenedor y los pods corren dentro de él. Por eso hay varias redes, una adentro de la otra:

| Red | Rango | Qué hay |
| :-- | :-- | :-- |
| Host | `127.0.0.1` | tu máquina |
| Red Docker `kind` | `172.x.0.0/16` | el contenedor-nodo |
| Pods | `10.244.0.0/16` | cada pod |
| Services | `10.96.0.0/16` | las IP virtuales |

**El camino de un request** (esto lo preguntan seguro):
```
curl http://localhost/catalog
 → puerto 80 de tu máquina
 → extraPortMappings de Kind → puerto 80 del contenedor-nodo
 → pod ingress-nginx (escucha con hostPort 80)
 → regla del Ingress: localhost → Service ui
 → kube-proxy traduce la IP del Service a la IP del pod ui:8080
 → la UI llama a catalog, carts, etc. por sus Services
```

**Para explorar:**
```bash
kubectl get pods -A -o wide       # mirá las IPs de cada pod
kubectl get svc -n the-store
kubectl get ingress -A
```

**Chequear los CIDR del diagrama.** En el diagrama pusimos `172.29.0.0/16` y `10.244.0.0/24`. Hay que confirmarlos contra el clúster real, porque la consigna pide que estén "con precisión". Kind suele usar `172.18.0.0/16`, y `/24` es el rango de *un* nodo dentro del `/16`. Si algo no coincide, corregimos el diagrama.
```bash
docker network inspect kind | jq '.[0].IPAM.Config'
kubectl get nodes -o jsonpath='{.items[0].spec.podCIDR}'
```

**Ver con qué IP te ve el Ingress.** Nos va a servir en el paso 6:
```bash
curl -s http://localhost/ > /dev/null
kubectl logs -n ingress-nginx deploy/ingress-nginx-controller --tail=3   # la 1.ª columna es tu IP
```

> 🤔 ¿Por qué el Ingress te ve con una IP `172.x.x.x` y no como `127.0.0.1`?

---

## 2. Atacar la tienda sin WAF

**Qué hacemos:** correr todos los `curl` de la pre-entrega contra la tienda desprotegida y guardar lo que pasa. Es el "antes" de la demo: sin esto, un 403 después no prueba nada.

- Armar `scripts/attacks/` con un script por sección de la pre-entrega (3.1 a 3.5).
- Guardar las salidas en `docs/evidencia/sin-waf/`.
- Mirar los efectos en vivo:
  ```bash
  kubectl get pods -n the-store -w          # en otra terminal
  curl -s http://localhost/utility/panic    # → el pod de la UI se reinicia: DoS remoto sin autenticación
  curl -s http://localhost/proxy/orders     # → todas las órdenes, con datos personales
  ```
- Ojo: `POST /utility/health/down` deja la UI caída hasta que se llama a `/utility/health/up`.

Los casos de `POST /catalog/products` van a dar 404/405, porque ese endpoint **todavía no existe** (lo armamos en el paso 3).

> 🤔 `orders` es un Service interno (`ClusterIP`). ¿Cómo puede ser que `/proxy/orders` lo exponga hacia afuera?

---

## 3. Crear el endpoint vulnerable

**Qué hacemos:** crear el `POST /catalog/products` "con vulnerabilidades controladas" que prometimos en la pre-entrega.

**Por qué hace falta.** The Store no tiene una SQLi real: Catalog usa GORM con consultas parametrizadas. Para *mostrar* que el WAF frena una SQLi que sí funciona, necesitamos un endpoint vulnerable a propósito.

```go
// Segura: el valor viaja separado del SQL y nunca se interpreta como código
db.Where("name LIKE ?", "%"+name+"%")

// Vulnerable: el valor se pega dentro del SQL
db.Raw("SELECT * FROM products WHERE name LIKE '%" + name + "%'")
// name = x%' OR 1=1--   →   ... LIKE '%x%' OR 1=1--%'   → devuelve TODO
```

Si además la respuesta es HTML con `name` sin escapar, un `<script>` en `name` se ejecuta en el browser: eso es **XSS reflejado**.

**El detalle del ruteo.** El tráfico entra por `Ingress → (WAF) → UI`, y la UI no tiene esa ruta. Si el endpoint vive solo en Catalog (Go), desde `localhost` no se puede llegar. Lo más limpio es:
- **Catalog (Go):** el endpoint vulnerable de verdad. Busca productos "similares" concatenando `name` en el SQL y responde HTML sin escapar.
- **UI (Java):** un `@PostMapping("/products")` en `CatalogController` que reenvía el body a `http://catalog/catalog/products` y devuelve lo que recibe.

Así se mantiene el diagrama (WAF → UI → microservicios). La alternativa sería rutear ese path directo a Catalog desde el NGINX del WAF, pero eso cambia la arquitectura que presentamos.

```bash
./local.sh reload-images && kubectl rollout restart deploy -n the-store catalog ui

curl -s -X POST -H "Content-Type: application/json" -d '{"name": "x%'\'' OR 1=1--"}' http://localhost/catalog/products   # todos los productos
curl -s -X POST -H "Content-Type: application/json" -d '{"name": "<script>alert(1)</script>"}' http://localhost/catalog/products   # el script aparece tal cual
```

Con esto completamos la evidencia "sin WAF" que había quedado pendiente en el paso 2.

> 🤔 Si el WAF ya lo bloquea, ¿está bien dejar código vulnerable? (No en la vida real: el WAF es una capa *extra*, no reemplaza arreglar el código. Acá lo dejamos solo para la demo.)

---

## 4. Meter el WAF en el medio

**Qué hacemos:** que todo el tráfico pase por `Ingress → WAF → UI`. Por ahora, sin bloquear nada.

**La imagen.** `owasp/modsecurity-crs:nginx` ya trae NGINX + ModSecurity + CRS, y se configura casi todo con variables de entorno: `BACKEND` (a dónde reenvía), `MODSEC_RULE_ENGINE`, `PARANOIA`, `ANOMALY_INBOUND`, las de audit log, etc. Usamos **un tag fijo** (no `latest`) y antes de escribir YAML miramos qué trae por dentro, porque los nombres y las rutas cambian entre versiones:
```bash
docker run --rm --entrypoint sh owasp/modsecurity-crs:<TAG> -c \
  'cat /etc/modsecurity.d/setup.conf; ls /etc/modsecurity.d/owasp-crs/rules'
```
La idea es encontrar dónde enganchar nuestras reglas para que corran **antes** del CRS (suele ser `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf`).

**Qué creamos** (en una carpeta `waf/`):
- `namespace.yaml`: el namespace `edge-security`.
- `deployment.yaml`: el WAF, con `BACKEND=http://ui.the-store.svc.cluster.local`, puerto 8080 y las reglas montadas.
- `service.yaml`: `ClusterIP` en el puerto 80 que apunta al 8080.
- `ingress.yaml`: `localhost → waf`. Tiene que estar en `edge-security`, porque un Ingress solo apunta a Services de su namespace.
- `kustomization.yaml`: arma todo con `kubectl apply -k waf/` y genera el ConfigMap de reglas desde los `.conf`. Como le agrega un hash al nombre, cada vez que cambiamos una regla el WAF se reinicia solo.

**Ojo con el Ingress original.** `dist/kubernetes.yaml` trae un Ingress que manda `localhost` **directo a la UI**. Si lo dejamos, hay un camino que esquiva el WAF. Hay que sacarlo del YAML y del clúster (`kubectl delete ingress ui -n the-store`).

**¿Por qué no usamos el ModSecurity que trae ingress-nginx?** Es lo que propone el análisis de endpoints, pero en la pre-entrega elegimos el WAF separado: ingress-nginx quedó discontinuado y, además, si el WAF falla o se actualiza, no rompe el ruteo de todo el clúster.

```bash
kubectl apply -k waf/
kubectl get ingress -A                         # solo tiene que quedar el de edge-security
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/catalog   # 200, ahora pasando por el WAF
kubectl logs -n edge-security deploy/waf -f    # el request aparece acá
```

> 🤔 ¿Qué pasa con la tienda si se cae el pod del WAF?

---

## 5. Modos, logs e IP real

**Qué hacemos:** poder prender y apagar el WAF, dejar armados los logs y lograr que el WAF vea la IP real del cliente.

**Modos del motor** (`MODSEC_RULE_ENGINE`):
- `Off`: no inspecciona nada. Es nuestro "**sin WAF**" para comparar: el tráfico hace el mismo recorrido y lo único que cambia es la inspección.
- `DetectionOnly`: evalúa y loguea, pero **no bloquea**. Sirve para calibrar.
- `On`: bloquea.

Armamos un `scripts/waf.sh mode on|detect|off` que por dentro hace `kubectl set env deploy/waf -n edge-security MODSEC_RULE_ENGINE=...`. Lo vamos a usar todo el tiempo para los "con y sin WAF" de la pre-entrega.

**Calibrar.** Con el WAF en `DetectionOnly`, navegamos la tienda y hacemos una compra completa. Si alguna regla salta con tráfico normal, es un **falso positivo** (por ejemplo, un apóstrofe en `O'Higgins 123`). Se arregla excluyendo esa regla para ese campo puntual, nunca apagando el CRS.

**Audit log.** En la pre-entrega dijimos "logs estructurados de **cada** transacción analizada", así que:
- `MODSEC_AUDIT_ENGINE=On`: todas las transacciones, no solo las sospechosas (eso sería `RelevantOnly`).
- `MODSEC_AUDIT_LOG_FORMAT=JSON`: los logs quedan "estructurados".
- `MODSEC_AUDIT_LOG=/dev/stdout`: se leen con `kubectl logs` y se filtran con `jq`.

```bash
kubectl logs -n edge-security deploy/waf | grep '^{"transaction"' | tail -1 \
  | jq '.transaction | {client_ip, uri: .request.uri, code: .response.http_code, rules: [.messages[].details.ruleId]}'
```

**La IP real.** El WAF recibe la conexión *desde el pod del Ingress*, así que sin hacer nada todas las requests parecen venir de `10.244.x.x`. El Ingress agrega el header `X-Real-IP` con la IP del cliente. Con el módulo `realip` de NGINX (`SET_REAL_IP_FROM=10.244.0.0/16`, `REAL_IP_HEADER=X-Real-IP`), el WAF usa esa IP como `REMOTE_ADDR`, pero **solo si la conexión viene de un rango confiable**. ¿Por qué esa condición? Porque cualquiera puede mandar un `X-Real-IP` inventado. El Ingress lo pisa con el valor real, así que solo podemos confiar en ese header cuando viene del Ingress.

Para verificarlo: en el log, `client_ip` tiene que ser la IP que viste en el paso 1, no la del pod del Ingress.

```bash
./scripts/waf.sh mode detect
curl -s -o /dev/null -w "%{http_code}\n" "http://localhost/catalog?tag=<script>alert(1)</script>"   # 200, pero queda logueado
./scripts/waf.sh mode on
curl -s -o /dev/null -w "%{http_code}\n" "http://localhost/catalog?tag=<script>alert(1)</script>"   # 403
```

---

## 6. Protección: paths sensibles + IP (3.1)

**Qué hacemos:** que `/utility/**`, `/proxy/**`, `/info`, `/topology` y `/actuator/**` den **403** desde afuera y sigan andando desde adentro del clúster.

Esta regla es nuestra: el CRS no conoce nuestros paths. Corre en **fase 1**, porque solo necesita el path y la IP. Y usa `deny` directo, sin puntaje, porque acá no hay nada que dudar.

```apache
SecRule REQUEST_FILENAME "@rx ^/(?:utility|proxy|actuator|info|topology)(?:[/;]|$)" \
    "id:10100,phase:1,deny,status:403,log,\
    t:none,t:urlDecodeUni,t:normalizePath,t:lowercase,\
    msg:'Endpoint interno desde IP no permitida',chain"
    SecRule REMOTE_ADDR "!@ipMatch 10.244.0.0/16,127.0.0.1"
```

**¿Por qué `REMOTE_ADDR` y no directamente el header `X-Real-IP`?** En la pre-entrega dijimos que tomábamos la IP de `X-Real-IP`, y es así: el header llega a `REMOTE_ADDR` gracias al paso 5. Pero si la regla mirara el header directo y un request llegara *sin* él, la regla no matchearía y el request **pasaría**. Eso se llama *fail-open*. Con `REMOTE_ADDR` siempre hay un valor para comparar.

**¿Por qué las transformaciones?** Porque un atacante va a probar `/Utility/panic`, `//utility/panic`, `/%75tility/panic`, `/catalog/../utility/panic`, `/proxy;x=1/orders`... Las probamos todas y tienen que dar 403.

**Probar desde adentro** (tiene que dar 200):
```bash
kubectl run tmp --rm -it --image=curlimages/curl -n the-store -- \
  curl -s -o /dev/null -w "%{http_code}\n" -H "Host: localhost" \
  http://ingress-nginx-controller.ingress-nginx.svc/actuator/health
```

**Dos limitaciones** que ya mencionamos en la pre-entrega y conviene tener claras:
- El tráfico pod→pod no pasa por el WAF: protegemos el **perímetro**.
- El IDOR sigue existiendo: le cerramos el camino por `/proxy`, pero la app sigue sin validar de quién es cada carrito.

> 🤔 ¿Qué pasa con `/UTILITY/panic`? ¿Y con `/catalog` (que empieza parecido pero es legítimo)?

---

## 7. Protección: query params (3.2)

**Qué hacemos:** que la SQLi y el XSS en `?tag=` den 403.

Acá **no escribimos reglas**: el trabajo lo hace el CRS. Lo importante es **entender qué regla saltó y por qué**:
- **942xxx** detecta SQLi y **941xxx** detecta XSS. Las 942100 y 941100 usan *libinjection*, que en lugar de usar regex "tokeniza" el input como si fuera SQL o HTML.
- La regla que detecta el ataque **solo suma puntos**. El que bloquea es la **949110**, cuando el total pasa el umbral. En el log se ven las dos.

```bash
curl -s -i "http://localhost/catalog?tag=1'%20OR%20'1'='1"
curl -s -i "http://localhost/catalog?tag=%3Cscript%3Ealert(1)%3C/script%3E"
curl -s -i "http://localhost/catalog?tag=tools"     # legítimo → 200
```

Anotamos los Rule IDs que aparecen **en el log** (no los asumimos) y los usamos en la PPT.

**Para jugar:** subir `ANOMALY_INBOUND` a 10 y ver qué deja de bloquearse. De paso, probar otros ataques que el CRS también cubre aunque no estén en la pre-entrega: `?tag=../../etc/passwd` (930xxx), `?tag=;cat /etc/passwd` (932xxx). Es solo para entender el alcance, no para presentarlo.

> 🤔 Si Catalog no es vulnerable a SQLi, ¿para qué bloquearla? (Defensa en profundidad: puede aparecer en una dependencia o en un cambio futuro.)

---

## 8. Protección: body (3.3)

**Qué hacemos:** que el WAF inspeccione el body de `POST /checkout` (formulario) y de `POST /catalog/products` (JSON).

- Para leer el body, el WAF lo tiene que **guardar entero** antes de reenviarlo. Eso cuesta memoria y tiempo, y por eso existe un límite de tamaño (paso 10).
- ModSecurity elige cómo parsearlo según el `Content-Type`:
  - formulario → `ARGS_POST:firstName`
  - JSON → `ARGS_POST:json.name`
- Como al final todo termina en `ARGS_POST`, **las mismas reglas 941/942 sirven para los dos formatos**. Esa es la idea que hay que transmitir en la demo.

```bash
curl -s -i -b "SESSIONID=11111111-1111-4111-8111-111111111111" -X POST \
  -d "firstName=<script>alert(1)</script>&lastName=Perez&address1=Calle123&city=CABA&state=CA&zipCode=10000&email=test@itba.edu.ar" \
  http://localhost/checkout
curl -s -i -X POST -H "Content-Type: application/json" -d '{"name": "x%'\'' OR 1=1--"}' http://localhost/catalog/products
curl -s -i -X POST -H "Content-Type: application/json" -d '{"name": "<script>alert(1)</script>"}' http://localhost/catalog/products
```

En el log se ve qué variable matcheó: `ARGS:firstName` en un caso y `ARGS:json.name` en el otro. Verificar también que una compra normal siga funcionando.

> 🤔 ¿Qué pasa si mando el JSON pero con `Content-Type: text/plain`?

---

## 9. Protección: headers y cookie (3.4)

**Qué hacemos:** bloquear scanners por User-Agent y cookies `SESSIONID` truchas. Las dos cosas en **fase 1**, porque solo miran headers.

**User-Agent.** La familia **913** del CRS reconoce herramientas como sqlmap o nikto. Son reglas críticas: con un solo match ya alcanza el umbral. Hay que ser honestos: se evade cambiando el User-Agent. Sirve contra el escaneo automático, no contra alguien que sabe lo que hace.

**Cookie.** La UI genera un UUID v4 como `SESSIONID`, pero **acepta cualquier valor** que le mande el cliente (lo hace `SessionIDWebFilter.java`). Si exigimos formato UUID, un atacante ya no puede probar `victima-123`, `1`, `2`, `3`... Ojo: si alguien roba un UUID válido, esto no lo frena.

```apache
SecRule REQUEST_COOKIES:SESSIONID "!@rx ^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$" \
    "id:10300,phase:1,deny,status:403,log,msg:'SESSIONID con formato invalido'"
SecRule &REQUEST_COOKIES:SESSIONID "@gt 1" \
    "id:10301,phase:1,deny,status:403,log,msg:'Mas de una cookie SESSIONID'"
```
Si la cookie **no viene** (primera visita), la regla no se evalúa y la UI crea una nueva, que es justo lo que queremos.

```bash
curl -s -i -A "sqlmap/1.7.2" http://localhost/              # 403
curl -s -i -b "SESSIONID=victima-123" http://localhost/cart # 403
curl -s -i http://localhost/cart                            # 200 + Set-Cookie
```

---

## 10. Protección: estructura del request (3.5)

**Qué hacemos:** que un JSON mal formado dé **400** y que un body demasiado grande dé **413**.

**JSON roto.** Si el parser de JSON falla, ModSecurity marca `REQBODY_ERROR`. La configuración base de la imagen trae una regla que en ese caso responde 400 (hay que confirmar que esté). ¿Por qué importa? Porque si el JSON no se puede parsear, **no se inspecciona**: sin esa regla, un JSON "roto a propósito" pasaría sin que nadie lo revise.

**Tamaño.** `SecRequestBodyNoFilesLimit` (en la imagen, `MODSEC_REQ_BODY_NOFILES_LIMIT`) define el máximo para JSON y formularios; lo fijamos explícitamente, por ejemplo en 128 KB. Hay un detalle: hay **dos NGINX** en el camino y los dos tienen límite. El Ingress corta en 1 MB por defecto. Para que el 413 lo dé *el WAF*, el payload tiene que pasar el límite del WAF pero no el del Ingress. Los 500 KB de la pre-entrega cumplen.

```bash
curl -s -i -X POST -H "Content-Type: application/json" -d '{"name": "hola",}' http://localhost/catalog/products   # 400
python3 -c 'print("{\"name\": \"" + "a"*500000 + "\"}")' | \
  curl -s -i -X POST -H "Content-Type: application/json" --data-binary @- http://localhost/catalog/products        # 413
```

> 🤔 Si mando 2 MB, ¿quién me devuelve el 413? ¿Cómo me doy cuenta mirando los logs?

---

## 11. HTTPS

**Qué hacemos:** servir `https://localhost`. En el diagrama de la pre-entrega pusimos `HTTP/HTTPS :80/:443`, así que entra en lo prometido.

- El TLS se **termina en el Ingress**: ahí se descifra y el tráfico sigue en HTTP hacia el WAF. Por eso el WAF puede inspeccionar HTTPS: lo recibe ya en claro.
- El tramo Ingress → WAF → UI queda sin cifrar dentro del clúster. Para la POC alcanza; la mejora sería mTLS entre pods.
- Generamos un certificado autofirmado para `localhost` (con `openssl` o `mkcert`), lo cargamos como Secret y lo agregamos al Ingress. **La clave privada no se commitea.**
- Ojo: con TLS configurado, ingress-nginx redirige HTTP → HTTPS (308) por defecto. Eso rompe los `curl http://...`. O pasamos todo a HTTPS, o desactivamos el redirect con la anotación `ssl-redirect: "false"`.

```bash
curl -k -s -o /dev/null -w "%{http_code}\n" "https://localhost/catalog?tag=1'%20OR%20'1'='1"   # 403
```

---

## 12. Cerrar los caminos alternativos

**Qué hacemos:** asegurarnos de que nadie llegue a la UI sin pasar por el WAF, y poner a prueba nuestras reglas.

- **NetworkPolicies.** Aunque el Ingress apunte al WAF, cualquier pod del clúster puede llamar a `ui.the-store` directo, o al WAF con un `X-Real-IP` falso. Con NetworkPolicies:
  - la UI solo acepta tráfico desde `edge-security`;
  - el WAF solo acepta tráfico desde `ingress-nginx`.

  Hay que **probar que el CNI de Kind las respete**: si no las soporta, las acepta sin quejarse y no hacen nada.
  ```bash
  kubectl run atacante --rm -it --image=curlimages/curl -- \
    curl -s -m 5 -o /dev/null -w "%{http_code}\n" http://ui.the-store/utility/headers
  # antes: 200 · después: timeout
  ```
- **Probar las reglas entre nosotros.** Cada uno intenta saltear una regla escrita por otro: encodings raros, mayúsculas, parámetros duplicados (`?tag=a&tag=<script>`), `Content-Type` cambiado. Lo que pase, se arregla o se anota como limitación.
- **2 réplicas del WAF** y límites de CPU y memoria, para que no sea un punto único de falla.

---

## 13. Scripts de tests y demo

**Qué hacemos:** que todo se pueda repetir con un comando y que la demo no dependa de tipear en vivo.

- `scripts/test-waf.sh`: una lista de requests con el código esperado (200/403/400/413). Imprime ✅/❌ por cada uno. Vamos sumando ahí todo lo que probamos en los pasos anteriores.
- `scripts/waf-logs.sh`: muestra el audit log en vivo, una línea por evento:
  ```
  10:31:02  172.18.0.1  GET /catalog?tag=...  403  [942100, 949110]  SQL Injection Attack Detected
  ```
- `scripts/demo.sh`: el guion de la demo, con pausas. Por cada protección: request legítimo (200) → ataque (403) → entrada en el log.
- Sumar el WAF a `local.sh` para que `./local.sh create-cluster` deje todo protegido de una.
- Prueba final: borrar el clúster, levantarlo de cero y correr `test-waf.sh`. Todo tiene que dar ✅.

---

## 14. How-to, PPT y ensayo

Lo que hay que subir: el **PDF de la pre-entrega**, la **PPT** y el **repo de GitHub con el how-to**.

- **`docs/HOWTO.md`:** cómo clonar, levantar, prender y apagar el WAF, correr los ataques, leer los logs y qué hacer si algo falla.
- **Diagrama:** actualizarlo con los CIDR reales y con HTTPS.
- **PPT (30 min máx.).** La consigna pide problema, solución, tecnología y una demo funcional:
  1. Problema: la evidencia "sin WAF" del paso 2.
  2. Arquitectura y el camino de un request.
  3. ModSecurity + CRS, anomaly scoring y por qué no elegimos las otras opciones.
  4. **Demo:** `demo.sh` y `waf-logs.sh` en paralelo.
  5. Limitaciones y qué mejoraríamos.
- **Hablan los tres.** Y los tres tienen que poder responder cualquier cosa: las preguntas 🤔 de cada paso son un buen simulacro.
- **Es on-line.** Definir quién comparte pantalla, usar una fuente grande en la terminal y tener el clúster levantado *antes* de entrar a la llamada.
- **Plan B:** una grabación de la demo completa, por si algo falla en vivo.

**Cosas para preguntarle a la cátedra:**
- Si en la revisión del 24/9 nos pidieron algún cambio, aunque haya sido de palabra (vale igual que lo escrito).
- Qué es exactamente el "documento final" que menciona la consigna en la evaluación.

---

## Referencia rápida

**Familias del CRS**

| IDs | Detecta |
| :-- | :-- |
| 913xxx | scanners (User-Agent) |
| 920xxx | violaciones del protocolo HTTP |
| 930xxx | path traversal / LFI |
| 931xxx | RFI |
| 932xxx | command injection |
| 941xxx | XSS |
| 942xxx | SQLi |
| 949110 | **el bloqueo por puntaje** |

Nuestras reglas usan IDs `10000–19999`; el CRS usa `900000+`.

**Comandos que vamos a usar todo el tiempo**
```bash
kubectl get pods -A -o wide
kubectl apply -k waf/
kubectl logs -n edge-security deploy/waf -f
kubectl set env deploy/waf -n edge-security MODSEC_RULE_ENGINE=On   # o DetectionOnly / Off
curl -s -o /dev/null -w "%{http_code}\n" <URL>
```
