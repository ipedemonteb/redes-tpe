# Bitácora — TPE WAF

Registro de avances del TP. Cada entrada dice **qué hicimos**, **por qué**, **qué vimos** (con la salida real de los comandos) y **qué quedó pendiente**. Sigue los pasos del [plan de trabajo](plan-de-trabajo.md).

| Paso | Estado |
| :-- | :-- |
| 0. Conceptos base | 📖 lectura |
| 1. Levantar el entorno | ✅ |
| 2. Atacar la tienda sin WAF | ✅ |
| 3. Crear el endpoint vulnerable | ✅ |
| 4. Meter el WAF en el medio | ✅ |
| 5. Modos, logs e IP real | ⏳ |
| 6–10. Protecciones 3.1 a 3.5 | ⏳ |
| 11. HTTPS | ⏳ |
| 12. Cerrar caminos alternativos | ⏳ |
| 13. Scripts de tests y demo | ⏳ |
| 14. How-to, PPT y ensayo | ⏳ |

### Prender y apagar el clúster

Todo el clúster es **un solo contenedor de Docker** (`the-store-control-plane`) que hace de nodo.

| Qué | Comando | Qué se pierde |
| :-- | :-- | :-- |
| Pausar | `docker stop the-store-control-plane` | solo datos en memoria (carritos, órdenes) |
| Reanudar | `docker start the-store-control-plane` y después `kubectl get pods -A` | — |
| Borrar todo | `./local.sh delete-cluster` | el clúster entero (las imágenes quedan en Docker) |
| Crear de cero | `./local.sh create-cluster --skip-tests` | — (tarda varios minutos) |
| Recompilar imágenes tras cambiar código | `./local.sh reload-images && kubectl rollout restart deploy -n the-store <servicio>` | — |

Si se cierra Docker Desktop, el nodo se apaga; al reabrirlo puede hacer falta `docker start the-store-control-plane`.

---

## 2026-10-24 — Revisión del plan y Paso 1

### Revisión del plan

Repasamos el plan contra la [pre-entrega](pre-entrega.md) y la [consigna](assignment.md). Está alineado: cada sección 3.x de la pre-entrega tiene su paso (6 a 10) y los `curl` que prometimos están en el plan. Cosas a tener en cuenta:

- **Fecha límite:** entrega el miércoles 4/11 a las 23:59, presentaciones el 5/11 y el 10/11. Quedan ~11 días.
- **Recursos de Docker:** Docker Desktop tiene **3 CPU y ~7,7 GB** asignados (el plan sugiere 4 CPU / 8 GB). Los pods de la tienda piden en total ~1 CPU (`requests`), así que debería alcanzar; si más adelante el WAF o los builds se arrastran, subir a 4 CPU en Docker Desktop → Settings → Resources.
- **ingress-nginx:** `local.sh` instala la versión fija `controller-v1.13.1` desde GitHub. Aunque el proyecto esté discontinuado, la URL sigue respondiendo (HTTP 200), así que no bloquea.
- **Diagrama:** queda pendiente confirmar los CIDR reales (lo hacemos al final de este paso).

### Paso 1 — Levantar el entorno

**Qué hicimos.** Verificamos las herramientas y corrimos `./local.sh create-cluster --skip-tests`.

| Herramienta | Versión |
| :-- | :-- |
| Docker Engine | 29.7.2 (arm64) |
| kind | v0.33.0 |
| kubectl | v1.36.1 |
| jq | ✅ |

**Qué hace `local.sh create-cluster` por dentro** (para poder explicarlo):

1. **`create_cluster`** — crea un clúster Kind de un solo nodo (`control-plane`) con:
   - la etiqueta `ingress-ready=true`, que el manifiesto de ingress-nginx para Kind usa para elegir en qué nodo correr;
   - `extraPortMappings` 80 y 443: Docker publica esos puertos del *contenedor-nodo* en tu máquina. Es lo que hace que `http://localhost` llegue al clúster.
2. **`install_ingress`** — aplica el manifiesto de ingress-nginx para Kind. El controller escucha con `hostPort: 80/443` en el nodo, así que recibe lo que entra por el mapeo anterior.
3. **`build_images`** — `docker build` de los 5 servicios (`catalog`, `cart`, `checkout`, `orders`, `ui`) con tag `latest`.
4. **`load_images`** — `kind load docker-image`: copia cada imagen de tu Docker al *containerd* del nodo. Hace falta porque el nodo es otro "Docker adentro de Docker" y no ve tus imágenes locales; por eso los Deployments no las bajan de ningún registry.
5. **`deploy_services`** — crea el namespace `the-store` y aplica `dist/kubernetes.yaml` (ServiceAccounts, ConfigMaps, Secrets, Services, Deployments y el Ingress `ui`).
6. `--skip-tests` saltea los tests E2E de Cypress, que tardan y no los necesitamos ahora.

**Resultado.** Terminó sin errores en ~10 min (14:00 → 14:11). El warning de `cpu-features` al compilar `checkout` es una dependencia opcional de Node y se puede ignorar (lo dice el propio mensaje).

#### Qué quedó corriendo

```
NAMESPACE      NAME                          IP
ingress-nginx  ingress-nginx-controller-...  10.244.0.7
the-store      catalog-...                   10.244.0.8
the-store      carts-...                     10.244.0.9
the-store      orders-...                    10.244.0.10
the-store      checkout-...                  10.244.0.11
the-store      ui-...                        10.244.0.12
kube-system    etcd, apiserver, kube-proxy,  172.18.0.2   ← usan la red del nodo (hostNetwork)
               kindnet...
```

- Los pods "de sistema" (etcd, apiserver, kube-proxy, kindnet) tienen la IP **del nodo** (`172.18.0.2`) porque corren con `hostNetwork`: no tienen red propia, comparten la del contenedor-nodo. Los demás pods tienen IP del rango de pods (`10.244.x.x`).
- Los 5 Services de la tienda son `ClusterIP` (`10.96.x.x`). Ninguno es accesible desde afuera por sí solo; lo único que entra es por el Ingress.
- El Service `ingress-nginx-controller` es `LoadBalancer` con `EXTERNAL-IP <pending>`: en Kind no hay quien le dé una IP externa, **y no importa**, porque el tráfico no entra por ese Service sino por el `hostPort: 80/443` del pod (confirmado en el spec del pod).
- El único Ingress es `the-store/ui` (`localhost → ui:80`). Usa la anotación vieja `kubernetes.io/ingress.class: nginx` en lugar de `ingressClassName`; en el nuestro (paso 4) conviene usar `ingressClassName: nginx`.

#### Pruebas desde afuera

```
/                  200
/catalog           200
/cart              200
/topology          200   ← expone la topología interna
/actuator/health   200   ← actuator expuesto
```

La tienda anda, y ya se ve parte del problema: `/topology` y `/actuator/**` responden desde afuera (es la evidencia que juntamos en el paso 2).

#### CIDR reales vs. diagrama de la pre-entrega

| Qué | Diagrama | Real | Cómo lo vimos |
| :-- | :-- | :-- | :-- |
| Red Docker `kind` | `172.29.0.0/16` | **`172.18.0.0/16`** (gateway `172.18.0.1`) | `docker network inspect kind` |
| IP del nodo | `172.29.0.x` | **`172.18.0.2`** | `kubectl get nodes -o wide` |
| Pods (clúster) | — | **`10.244.0.0/16`** | `podSubnet` en `kubeadm-config` |
| Pods (este nodo) | `10.244.0.0/24` | `10.244.0.0/24` ✅ | `.spec.podCIDR` del nodo |
| Services | `10.96.0.0/16` | `10.96.0.0/16` ✅ | `serviceSubnet` en `kubeadm-config` |
| SO del nodo | — | Debian GNU/Linux 13, containerd 2.3.4, K8s v1.37.0 | `kubectl get nodes -o wide` |
| CNI | — | kindnet | `kubectl get ds -n kube-system` |

**Correcciones para el diagrama:**
1. Docker Bridge `172.29.0.0/16` → `172.18.0.0/16` e IP del nodo `172.18.0.2`. Ojo: Docker elige ese rango al crear la red `kind` y **puede variar entre máquinas** (el `172.29` seguramente salió de otra compu). Para la demo vale el de la máquina que comparta pantalla. Si queremos que sea igual en todas, se puede crear la red antes del clúster: `docker network create kind --subnet 172.18.0.0/16`.
2. El Pod CIDR y el Service CIDR están dibujados **adentro del namespace `the-store`**, pero no son de un namespace: son de todo el clúster (el pod del Ingress también es `10.244.0.7`). Conviene moverlos al recuadro del nodo/clúster y poner `10.244.0.0/16` (clúster) y `10.244.0.0/24` (nodo).
3. Agregar el SO del nodo (Debian 13 + containerd), porque la consigna pide sistemas operativos.

#### Con qué IP nos ve el Ingress

```
172.18.0.1 - - [24/Oct/2026:17:12:22 +0000] "GET / HTTP/1.1" 200 ... [the-store-ui-80] [] 10.244.0.12:8080 ...
```

Y los headers que el Ingress le agrega a la request antes de pasársela a la UI (vistos con `/utility/headers`):

```json
"X-Real-IP": ["172.18.0.1"], "X-Forwarded-For": ["172.18.0.1"], "X-Forwarded-Proto": ["http"]
```

> 🤔 **¿Por qué `172.18.0.1` y no `127.0.0.1`?** `127.0.0.1` es el loopback de *tu Mac* y solo tiene sentido adentro de tu Mac. Cuando hacés `curl localhost:80`, Docker (que en macOS corre dentro de una VM Linux) recibe la conexión en el puerto publicado y **abre una conexión nueva** hacia el contenedor-nodo por la red `kind`. Esa conexión sale desde el **gateway** de esa red, `172.18.0.1`. Por eso, para el clúster, todo cliente externo es `172.18.0.1`.

**Por qué nos importa:**
- En el **paso 5** el WAF va a recibir las conexiones desde el pod del Ingress (`10.244.0.7`). Para ver la IP real tiene que leer `X-Real-IP`, que ya confirmamos que el Ingress agrega.
- En el **paso 6** la allowlist es `10.244.0.0/16,127.0.0.1`. Como desde afuera somos `172.18.0.1`, quedamos **fuera** de la allowlist → 403, que es lo que queremos.
- Limitación para mencionar: en esta POC todos los clientes externos se ven con la misma IP, así que no se podría, por ejemplo, bloquear a un atacante puntual por IP.

#### Cierre del paso 1
Fase 1 completada: el clúster está levantado y la tienda funciona en `http://localhost`.

---

## 2026-10-24 — Paso 2: atacar la tienda sin WAF

**Qué hicimos.** Scripts en `scripts/attacks/` (uno por sección 3.x + `run-all.sh`) que corren los ataques de la pre-entrega e imprimen todo por terminal. No guardan nada en `docs/`.

**Resultado:** todos los ataques pasan sin filtro (es el "antes" de la demo). Revisamos que cada caso demuestre de verdad la vulnerabilidad, y en el camino aparecieron diferencias con la pre-entrega que hay que tener presentes:

- **IDOR de carritos (3.1):** el script primero carga un ítem en el carrito de `victima-123` por el flujo normal y después lo lee por `/proxy/carts/victima-123`. Así se ve el contenido ajeno, no un carrito vacío.
- **`/proxy/orders` (3.1):** responde 200 desde afuera (la vulnerabilidad es la exposición del Service interno). Está vacío porque no hay órdenes; cargar una requiere datos de pago, así que no lo automatizamos.
- **`health/down` (3.1):** marca `/actuator/health` como DOWN (503), **pero el grupo readiness sigue UP**, así que Kubernetes no saca el pod y la UI sigue atendiendo. Degrada el reporte de salud, no el servicio. El plan lo daba como "deja la UI caída"; no es así.
- **`panic` (3.1):** sí apaga el pod; Kubernetes lo reinicia (sube el contador de RESTARTS). DoS real aunque transitorio.
- **Query params (3.2):** Catalog no es explotable (consulta parametrizada; el `tag` se refleja escapado). El payload igual llega sin filtro → el WAF acá es defensa en profundidad. Lo dejamos dicho con honestidad.
- **Checkout XSS (3.3):** dos correcciones respecto de la pre-entrega:
  1. el campo del formulario es **`streetAddress`**, no `address1`;
  2. el `POST /checkout` necesita que la sesión tenga carrito **y** que se haya hecho un `GET /checkout` antes; si no, da 500 sin procesar. Con eso preparado, responde 200 y el `<script>` queda **guardado sin escapar** (se ve en `/proxy/checkout/<sid>`): XSS almacenado confirmado.
- **Cookie (3.4):** la app acepta `SESSIONID=victima-123` tal cual (no hay `Set-Cookie`); sin cookie, asigna un UUID. Prueba limpia de que no valida el formato.
- **`/catalog/products` (3.3 y 3.5):** da 405 en los 4 casos porque el endpoint todavía no existe. Se crea en el paso 3 y ahí completamos esa evidencia.

**Verificación.** `run-all.sh` corre de punta a punta y los casos clave quedan demostrados: IDOR muestra el carrito ajeno, el checkout responde 200 con el `<script>` almacenado sin escapar, `health/down` degrada el reporte (readiness UP) y `panic` reinicia el pod. Los 405 de `/catalog/products` quedan a la espera del paso 3.

> Detalle cosmético: correr el script varias veces acumula ítems repetidos en los carritos de prueba y suma un reinicio por el `panic`. No afecta la demostración; se puede dejar idempotente más adelante.

> Pendiente para el documento final: corregir en la pre-entrega `address1` → `streetAddress` y suavizar el claim de `health/down`.

---

## 2026-10-24 — Paso 3: endpoint vulnerable `POST /catalog/products`

**Qué hicimos.** Creamos el endpoint "con vulnerabilidades controladas" que faltaba (SQLi + XSS reflejado), repartido en dos servicios para no romper la arquitectura `Ingress → WAF → UI → microservicio`.

**Catalog (Go) — la vulnerabilidad real:**
- `repository/repository.go`: método `SearchProductsByName` que **concatena `name` directo en el SQL** (`SELECT ... WHERE name LIKE '%<name>%'`) vía `db.Raw`, sin parametrizar → SQLi.
- `api/catalog.go`: wrapper `SearchProductsByName`.
- `controller/controller.go`: handler `CreateProduct` (bind del JSON `{name}`) que devuelve **HTML con `name` sin escapar** → XSS reflejado.
- `main.go`: ruta `catalog.POST("/products", c.CreateProduct)`.

**UI (Java) — el puente:**
- `web/CatalogController.java`: `@PostMapping("/products")` con `WebClient` que reenvía el body JSON a `http://catalog/catalog/products` y devuelve la respuesta tal cual (incluido el status, con `exchangeToMono`). No sanitiza nada a propósito.

**Build.** `go` no está instalado local; la compilación de Go y Java ocurre en Docker. `./local.sh reload-images` compiló las dos imágenes sin errores y después `kubectl rollout restart deploy -n the-store catalog ui`.

**Verificación (vía UI, como entra el tráfico real):**

| Caso | Resultado |
| :-- | :-- |
| `{"name":"Aqua"}` (normal) | 200, devuelve solo "Aqua Ace GT" (filtra bien) |
| `{"name":"x%' OR 1=1--"}` (SQLi) | 200, devuelve **los 12 productos** → inyección confirmada |
| `{"name":"<script>alert(1)</script>"}` (XSS) | 200, el `<script>` vuelve **sin escapar** → XSS confirmado |
| `{"name":"hola",}` (JSON roto, 3.5) | 400, Catalog no puede parsear |
| body ~500 KB (3.5) | 500, el payload llega al backend y lo rompe (`LIKE pattern too complex`) |

Con esto, los 405 del paso 2 quedaron resueltos: `scripts/attacks/3.3` y `3.5` ahora muestran los ataques reales. Actualizamos sus notas (sacamos los "todavía no existe" y aclaramos qué cambia con WAF: el 400/413 pasará a darlo el borde).

> Recordatorio: el código vulnerable queda a propósito sólo para la POC. En producción el WAF es una capa extra, no reemplaza arreglar el código. Los métodos llevan comentarios `VULNERABLE A PROPÓSITO (POC WAF)`.

---

## 2026-10-24 — Paso 4: meter el WAF en el medio

**Qué hicimos.** Armamos la carpeta `waf/` con los 4 manifiestos que describe el plan y los aplicamos al clúster. El motor de ModSecurity queda **apagado** (`MODSEC_RULE_ENGINE=Off`): este paso es solo lograr que el tráfico pase por `Ingress → WAF → UI`, no bloquear nada todavía (eso arranca en el paso 6).

**Elegir el tag de la imagen.** La pre-entrega dice `owasp/modsecurity-crs:nginx`, pero esa etiqueta es flotante. Inspeccionamos el tag en Docker Hub y encontramos el equivalente fijo: **`4.30.0-nginx-202610180210`** (CRS 4.30.0, variante nginx, build del 18/10/2026). Confirmamos que apunta al mismo digest que `nginx` en este momento, así que es la misma imagen con un nombre que no va a cambiar solo.

**Qué vimos al inspeccionar la imagen** (`docker run --rm --entrypoint sh owasp/modsecurity-crs:nginx -c 'env; ls .../rules'`):
- Puerto de escucha interno: **8080**.
- Variable de backend: **`BACKEND`** (default `http://localhost:80`).
- Motor: **`MODSEC_RULE_ENGINE`** (default `on`).
- Para el paso 5 ya quedan anotadas `SET_REAL_IP_FROM` (default `127.0.0.1`) y `REAL_IP_HEADER` (default `X-REAL-IP`).
- `/etc/modsecurity.d/owasp-crs/rules/` trae las 855 reglas del CRS completo (familias 900 a 999) más `REQUEST-900-EXCLUSION-RULES-BEFORE-CRS.conf.example`, que es donde van a enganchar nuestras reglas propias (paso 6+).

**Qué creamos en `waf/`:**
- `namespace.yaml`: namespace `edge-security`, separado de `the-store` y de `ingress-nginx`. Es la materialización concreta del desacople que propusimos en la pre-entrega (sección 5): el WAF es un componente propio, no un módulo de ingress-nginx.
- `deployment.yaml`: 1 réplica, `BACKEND=http://ui.the-store.svc.cluster.local` (FQDN completo porque el Service `ui` vive en otro namespace), `MODSEC_RULE_ENGINE=Off`, límites de CPU/memoria.
- `service.yaml`: `ClusterIP` 80→8080.
- `ingress.yaml`: `localhost → Service waf`, en `edge-security` (un Ingress solo puede apuntar a Services de su propio namespace, por eso no podía estar en `the-store`).
- `kustomization.yaml`: junta los 4 archivos para `kubectl apply -k waf/`.

**Sacamos el Ingress viejo.** `dist/kubernetes.yaml` traía un Ingress `ui` que mandaba `localhost` directo al Service de la UI. Lo borramos del clúster (`kubectl delete ingress ui -n the-store`) y del archivo fuente, dejando un comentario explicando por qué: si quedaba, era un camino que esquivaba el WAF por completo.

**Problema al cargar la imagen al nodo kind.** `kind load docker-image owasp/modsecurity-crs:4.30.0-nginx-202610180210 --name the-store` falló:
```
ERROR: failed to load image: ... ctr: content digest sha256:0205eea1... not found
```
La imagen en Docker Hub es un *manifest list* multi-arquitectura que incluye entradas de "attestation" sin contenido real (`architecture: unknown`), y el comando que usa `kind` por dentro (`ctr images import --all-platforms`) no las sabe manejar. Lo resolvimos pidiéndole al nodo que la descargue él mismo, sin pasar por `kind load`:
```bash
docker exec the-store-control-plane ctr --namespace=k8s.io images pull docker.io/owasp/modsecurity-crs:4.30.0-nginx-202610180210
```
Así el nodo baja únicamente la plataforma que le corresponde (`arm64` en esta Mac) y evita el bug. Vale la pena recordarlo si se recrea el clúster de cero.

**Verificación:**

| Prueba | Resultado |
| :-- | :-- |
| `kubectl get pods -n edge-security` | `waf-...` en `Running`, sin reinicios |
| `kubectl get ingress -A` | Un solo Ingress: `edge-security/waf` (el de `the-store/ui` ya no existe) |
| `curl http://localhost/` y `/catalog` | `200` (pasan por `Ingress → WAF → UI`) |
| `curl "http://localhost/catalog?tag=<script>..."` | `200` (motor en `Off`, todavía no bloquea nada — es lo esperado en este paso) |
| `kubectl logs -n edge-security deploy/waf` | Aparecen las requests, logueadas con la IP del pod del Ingress (`10.244.0.7`) como cliente; `ModSecurity-nginx v1.0.4 (rules loaded ... 855 ...)` confirma que el CRS cargó |

Con esto, la cadena `Ingress → WAF → UI` que propusimos en la pre-entrega ya es real en el clúster. Falta: IP real del cliente vía `X-Real-IP` + modos on/detect/off + audit log estructurado (paso 5).
