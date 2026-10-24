# Bitácora — TPE WAF

Registro de avances del TP. Cada entrada dice **qué hicimos**, **por qué**, **qué vimos** (con la salida real de los comandos) y **qué quedó pendiente**. Sigue los pasos del [plan de trabajo](plan-de-trabajo.md).

| Paso | Estado |
| :-- | :-- |
| 0. Conceptos base | 📖 lectura |
| 1. Levantar el entorno | ✅ |
| 2. Atacar la tienda sin WAF | ⏳ |
| 3. Crear el endpoint vulnerable | ⏳ |
| 4. Meter el WAF en el medio | ⏳ |
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
