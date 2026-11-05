# How-to: implementación del WAF sobre The Store

## 1. Qué se implementó

The Store es una tienda de microservicios sobre Kubernetes cuyo único punto de entrada es
un Ingress NGINX sin inspección de capa 7. Agregamos un WAF (ModSecurity v3 + OWASP Core
Rule Set) como componente desacoplado entre el Ingress y la UI, en su propio namespace
`edge-security`. Todo el tráfico externo queda:

```
cliente → Ingress NGINX → WAF (ModSecurity + CRS) → UI → microservicios
```

El WAF inspecciona cada request, bloquea los maliciosos (`403`/`400`/`413`) y emite un
audit log estructurado (JSON) de cada transacción. El código de los microservicios no se
toca: toda la protección está en el borde.

Cinco protecciones (las de la pre-entrega §3):

| # | Qué protege | Cómo |
| :-- | :-- | :-- |
| 3.1 | Endpoints internos (`/utility`, `/proxy`, `/actuator`, `/info`, `/topology`) | Regla propia `10100`: 403 si la IP no es del clúster |
| 3.2 | SQLi / XSS en query params | OWASP CRS (941/942) + anomaly scoring (949110) |
| 3.3 | SQLi / XSS en el body (form y JSON) | OWASP CRS sobre `ARGS_POST` |
| 3.4 | Scanners y cookie `SESSIONID` / `X-Forwarded-Prefix` | CRS 913xxx + reglas propias `10300`/`10301`/`10302` |
| 3.5 | Requests mal formados o enormes | Reglas propias `10400` (413) / `10401` (400) |

## 2. Requisitos

- Docker corriendo (con ~4 CPU / 8 GB para el clúster).
- kind (Kubernetes en Docker), kubectl y jq.

```bash
# macOS
brew install kind kubectl jq
# Linux: ver kind.sigs.k8s.io y kubernetes.io/docs/tasks/tools
```

Verificar:

```bash
docker info >/dev/null && kind version && kubectl version --client && jq --version
```

## 3. Levantar todo

El clúster de The Store y el WAF se levantan por separado (el WAF no está integrado a
`local.sh` todavía; ver [§9](#9-limitaciones-conocidas)).

```bash
# 1. Clúster kind + ingress-nginx + los 5 microservicios
./local.sh create-cluster --skip-tests

# 2. El WAF (namespace edge-security + Deployment + Service + Ingress + reglas)
kubectl apply -k waf/

# 3. Prender el motor de ModSecurity (el YAML lo deja en Off a propósito)
./scripts/waf.sh mode on
```

Comprobar que quedó todo arriba:

```bash
kubectl get pods -n the-store         # los 5 servicios Running
kubectl get pods -n edge-security     # el pod waf Running
kubectl get ingress -A                # debe quedar SOLO el de edge-security
curl -s -o /dev/null -w "%{http_code}\n" http://localhost/   # 200
```

La tienda queda en http://localhost.

> Ojo: `kubectl apply -k waf/` vuelve a poner el motor en `Off` (el `deployment.yaml` es la
> fuente de verdad). Cada vez que apliques, volvé a correr `./scripts/waf.sh mode on`.

## 4. Operar el WAF

### Modo del motor

```bash
./scripts/waf.sh mode on       # inspecciona y bloquea
./scripts/waf.sh mode detect   # inspecciona y loguea, pero NO bloquea (para calibrar)
./scripts/waf.sh mode off      # no inspecciona nada: es el "sin WAF" para comparar
./scripts/waf.sh status        # muestra el modo actual
```

Cambiar de modo reinicia el pod y tarda ~10-15 s (el script espera a que termine). En la
demo, cambiá el modo antes de empezar a mostrar los ataques.

### Verificar que todo funciona (suite de tests)

```bash
./scripts/test-waf.sh
```

Corre ~22 casos (legítimos → 200, ataques → 403/400/413) e imprime ✅/❌ por cada uno.
Prende el motor si hace falta y lo restaura al salir. Sale con código ≠ 0 si algo falla:
sirve para la prueba "levantar de cero y que dé todo verde".

## 5. Correr la demo

La demo usa los scripts de `scripts/attacks/`, uno por punto del POC. Cada uno corre los
comandos de la pre-entrega e imprime el comando, el código HTTP y el comienzo de la
respuesta. **El mismo script sirve con el WAF apagado o prendido**: no consulta el modo, y
después de cada request muestra una nota según lo que respondió (si se bloqueó, qué regla
lo frenó; si pasó, qué vulnerabilidad queda expuesta).

Orden de la exposición:

```bash
# 0. Arquitectura
kubectl get pods -A
kubectl get ingress -A

# 1 a 5. Cada punto, primero sin WAF y después con WAF
./scripts/waf.sh mode off
./scripts/attacks/3.1-paths-ip.sh     # sin WAF: el ataque pasa
./scripts/waf.sh mode on
./scripts/attacks/3.1-paths-ip.sh     # con WAF: el ataque se bloquea
# ... lo mismo con 3.2-query-params, 3.3-body, 3.4-headers y 3.5-estructura

# 6. Logs (el WAF queda prendido)
./scripts/waf-logs.sh -n 20
```

Cada cambio de modo reemplaza el pod del WAF y borra su audit log: al final solo quedan
los eventos del último punto. Para correr los cinco de una: `./scripts/attacks/run-all.sh`.

> Con el WAF en `off`, el `3.1-paths-ip.sh` dispara `/utility/panic`, que tira la UI de
> verdad, y espera a que Kubernetes la reinicie (~25 s). Con el WAF en `on` el panic se
> bloquea (403) y el script termina en el acto.

Además hay dos guiones alternativos:

```bash
./scripts/demo.sh                 # recorre los 5 puntos con el WAF prendido (legítimo → 200, ataque → bloqueado)
./scripts/demo.sh --sin-waf       # agrega el ataque con el WAF apagado antes de cada punto
./scripts/demo-logs.sh            # dispara un mix de tráfico y muestra el audit log
```

## 6. Leer los logs (auditoría)

El WAF emite el audit log en JSON a `stdout`. El visor lo formatea legible:

```bash
./scripts/waf-logs.sh              # sigue el log en vivo (Ctrl-C para salir)
./scripts/waf-logs.sh -n 20        # últimas ~20 transacciones y sale
./scripts/waf-logs.sh --blocked    # solo las bloqueadas (código ≥ 400)
./scripts/waf-logs.sh -n 50 --blocked
```

Cada línea: `hora  IP_cliente  MÉTODO /uri  CÓDIGO  [reglas que dispararon]  mensaje`.

Crudo, sin el visor:

```bash
kubectl logs -n edge-security deploy/waf | grep '^{"transaction"' | tail -1 \
  | jq '.transaction | {client_ip, uri: .request.uri, code: .response.http_code, rules: [.messages[].details.ruleId]}'
```

## 7. Cómo está armado (estructura del repo)

```
waf/
├── namespace.yaml        # namespace edge-security
├── deployment.yaml       # el WAF: imagen owasp/modsecurity-crs, env (modo, límites, audit, realip)
├── service.yaml          # ClusterIP 80 → 8080
├── ingress.yaml          # todo el tráfico (cualquier host) → Service waf (único punto de entrada)
├── kustomization.yaml    # arma todo con `kubectl apply -k waf/`; genera los ConfigMap
├── nginx/realip.conf     # que el WAF vea la IP real del cliente (X-Real-IP → REMOTE_ADDR)
└── modsec/custom-rules.conf   # NUESTRAS reglas (IDs 10000-19999): 10100, 10300/01/02, 10400/01

scripts/
├── waf.sh          # cambiar el modo del motor / ver estado
├── test-waf.sh     # suite de tests (✅/❌)
├── demo.sh         # guion de la demo (cada punto del POC, con pausas)
├── demo-logs.sh    # demo de monitoreo (mix de tráfico + audit log)
├── waf-logs.sh     # visor del audit log
└── attacks/        # un script por punto (3.1 a 3.5), sirve con el WAF apagado o prendido
```

La imagen `owasp/modsecurity-crs` trae NGINX + ModSecurity v3 + el CRS completo. Nuestras
reglas se montan como un `.conf` dentro de `/etc/modsecurity.d/owasp-crs/rules/`, que la
imagen incluye automáticamente. El detalle del mecanismo (ConfigMap, Kustomize, el truco
del hash, volúmenes) está en [`explicaciones.md`](explicaciones.md) §2-6.

## 8. Cambiar o agregar una regla

```bash
vim waf/modsec/custom-rules.conf      # editar / agregar la regla (ID 10000-19999)
kubectl apply -k waf/                 # Kustomize recalcula el hash → reinicia el pod solo
./scripts/waf.sh mode on              # el apply dejó el motor en Off
./scripts/test-waf.sh                 # verificar que no se rompió nada
```

Si la regla tiene un error de sintaxis, el pod nuevo no pasa el `readinessProbe` y sigue
sirviendo el pod viejo: config rota no llega a producción. Por qué funciona así, en
[`explicaciones.md`](explicaciones.md) §6.

## 9. Limitaciones conocidas

Pensadas para las preguntas de la defensa:

- El WAF protege el perímetro. El tráfico pod→pod dentro del clúster no lo atraviesa.
- El IDOR sigue existiendo en la app: el WAF le cierra el camino externo por `/proxy`, pero
  la lógica sigue sin validar titularidad. Es un parche virtual y la vulnerabilidad queda.
- El filtro por User-Agent se evade cambiando el User-Agent. Sirve contra escaneo
  automático; un atacante que sabe lo que hace lo pasa de largo.
- La auditoría genera logs pero no los retiene. Se emiten en JSON a stdout y se leen con
  `kubectl logs`, que es efímero. Centralizar y retener (EFK/Loki) es otro módulo del TPE y
  queda fuera de scope.
- El WAF no está integrado a `local.sh`: se aplica a mano con `kubectl apply -k waf/`.
- Código vulnerable a propósito: `POST /catalog/products` tiene SQLi/XSS controlados, solo
  para que el WAF tenga ataques reales que bloquear en la demo (marcado con
  `VULNERABLE A PROPÓSITO (POC WAF)` en el código). No es para producción.

## 10. Troubleshooting

| Síntoma | Causa probable / arreglo |
| :-- | :-- |
| `curl http://localhost/` da `000` o no conecta | El clúster no está arriba o el Ingress no tomó el puerto 80. `kubectl get pods -A`; revisar que no haya otro clúster kind ocupando los puertos 80/443. |
| Los ataques dan `200` en vez de `403` | El motor está en `Off`. `./scripts/waf.sh status` y `./scripts/waf.sh mode on`. |
| Pod del WAF en `ContainerCreating` con `configmap not found` | Falta `namespace: edge-security` en el `configMapGenerator` (ya está en el repo). Reaplicar `kubectl apply -k waf/`. |
| `502` justo después de cambiar de modo | El pod viejo se está reemplazando. El `waf.sh` ya espera el rollout; reintentá el request. |
| El audit log muestra `client_ip: 10.244.x.x` (IP del Ingress) | Falta la config de `realip` a nivel `http`. Está en `waf/nginx/realip.conf`; reaplicar. |
| `kind load docker-image` falla con `content digest ... not found` | Bug con imágenes multi-arch. Bajar la imagen desde el nodo: `docker exec the-store-control-plane ctr --namespace=k8s.io images pull docker.io/owasp/modsecurity-crs:<tag>`. |

Apagar / prender el clúster sin borrarlo:

```bash
docker stop the-store-control-plane     # pausar (se pierden carritos/órdenes en memoria)
docker start the-store-control-plane    # reanudar; después: kubectl get pods -A
./local.sh delete-cluster               # borrar todo
```
