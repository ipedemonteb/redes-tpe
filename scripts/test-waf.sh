#!/bin/bash
# Suite de tests del WAF: una lista de requests con el codigo HTTP esperado.
# Imprime OK/FALLA por cada uno y un resumen. Sale con codigo != 0 si algo falla.
#
#   ./scripts/test-waf.sh
#
# Necesita el WAF con el motor en "On" (si no lo esta, lo prende y lo restaura al
# terminar). Los casos son los mismos que verificamos a mano en los pasos 3.1 a 3.5.
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost}"
NAMESPACE="edge-security"
DEPLOYMENT="waf"
DIR="$(dirname "$0")"

GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; GRAY='\033[0;90m'; BOLD='\033[1m'; NC='\033[0m'

PASS=0; FAIL=0; TOTAL=0

section() {
    echo
    echo -e "${BOLD}${BLUE}── $1${NC}"
}

# check "descripcion" CODIGO_ESPERADO <args de curl...>
check() {
    local desc="$1" expected="$2"; shift 2
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 "$@")
    TOTAL=$((TOTAL + 1))
    if [ "$code" = "$expected" ]; then
        PASS=$((PASS + 1))
        printf "  ${GREEN}✅ %-3s${NC} ${GRAY}(esperado %s)${NC}  %s\n" "$code" "$expected" "$desc"
    else
        FAIL=$((FAIL + 1))
        printf "  ${RED}❌ %-3s${NC} ${GRAY}(esperado %s)${NC}  %s\n" "$code" "$expected" "$desc"
    fi
}

current_mode() {
    kubectl get deploy "$DEPLOYMENT" -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="MODSEC_RULE_ENGINE")].value}' 2>/dev/null
}

# --- Preparacion: WAF levantado y en modo On ---------------------------------
if ! kubectl get deploy "$DEPLOYMENT" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "No encuentro el deployment $DEPLOYMENT en $NAMESPACE. ¿Esta levantado el WAF?" >&2
    exit 1
fi

ORIG_MODE="$(current_mode)"
RESTORE_MODE=""
if [ "$ORIG_MODE" != "On" ]; then
    echo "El WAF esta en modo '${ORIG_MODE:-?}'. Lo paso a On para correr los tests…"
    bash "$DIR/waf.sh" mode on
    RESTORE_MODE="$ORIG_MODE"
fi

restore() {
    if [ -n "$RESTORE_MODE" ]; then
        echo
        echo "Restaurando el WAF a modo '$RESTORE_MODE'…"
        bash "$DIR/waf.sh" mode "$(echo "$RESTORE_MODE" | tr '[:upper:]' '[:lower:]' | sed 's/detectiononly/detect/')" >/dev/null 2>&1 || true
    fi
}
trap restore EXIT

echo -e "${BOLD}Suite de tests del WAF${NC}  (BASE_URL=$BASE_URL, motor=On)"

# --- Trafico legitimo: tiene que pasar (200) ---------------------------------
section "Trafico legitimo (no se bloquea)"
check "Home de la tienda"                       200 "$BASE_URL/"
check "Catalogo con tag normal"                 200 "$BASE_URL/catalog?tag=shoes"
check "Alta de producto con nombre normal"      200 -X POST -H "Content-Type: application/json" \
    -d '{"name": "shoes"}' "$BASE_URL/catalog/products"
check "Cookie SESSIONID con UUID v4 valido"     200 \
    -b "SESSIONID=11111111-1111-4111-8111-111111111111" "$BASE_URL/cart"
check "Sin cookie (la app asigna una)"          200 "$BASE_URL/cart"

# --- 3.1 Paths internos desde afuera: 403 ------------------------------------
section "3.1 Endpoints internos desde afuera (regla propia 10100)"
check "Ordenes de clientes (/proxy)"            403 "$BASE_URL/proxy/orders"
check "Metricas de Actuator"                    403 "$BASE_URL/actuator/metrics"
check "Health de Actuator"                      403 "$BASE_URL/actuator/health"
check "Carrito ajeno por ID (IDOR)"             403 "$BASE_URL/proxy/carts/victima-123"
check "Marcar la UI como no saludable"          403 -X POST "$BASE_URL/utility/health/down"
check "Apagar la UI (DoS)"                       403 "$BASE_URL/utility/panic"

# --- 3.2 Query params: SQLi/XSS -> 403 (CRS) ---------------------------------
section "3.2 Query parameters (CRS anomaly scoring)"
check "SQLi en ?tag"                            403 "$BASE_URL/catalog?tag=1'%20OR%20'1'='1"
check "XSS en ?tag"                             403 "$BASE_URL/catalog?tag=%3Cscript%3Ealert(1)%3C/script%3E"

# --- 3.3 Body (urlencoded y JSON): SQLi/XSS -> 403 (CRS) ---------------------
section "3.3 Body del request (CRS anomaly scoring)"
check "XSS en form urlencoded (firstName)"      403 -X POST \
    -d "firstName=<script>alert(1)</script>&lastName=Perez" "$BASE_URL/checkout"
check "SQLi en body JSON"                        403 -X POST -H "Content-Type: application/json" \
    -d '{"name": "x'"'"' OR 1=1--"}' "$BASE_URL/catalog/products"
check "XSS en body JSON"                          403 -X POST -H "Content-Type: application/json" \
    -d '{"name": "<script>alert(1)</script>"}' "$BASE_URL/catalog/products"

# --- 3.4 Headers y cookie ----------------------------------------------------
section "3.4 Headers y cookie"
check "User-Agent de sqlmap (CRS 913100)"       403 -A "sqlmap/1.7.2" "$BASE_URL/"
check "SESSIONID sin formato UUID (regla 10300)" 403 \
    -b "SESSIONID=victima-123" "$BASE_URL/cart"
check "Dos cookies SESSIONID (regla 10301)"     403 \
    -H "Cookie: SESSIONID=11111111-1111-4111-8111-111111111111; SESSIONID=22222222-2222-4222-8222-222222222222" \
    "$BASE_URL/cart"
check "Header X-Forwarded-Prefix (regla 10302)" 403 \
    -H "X-Forwarded-Prefix: //evil.com" "$BASE_URL/home"

# --- 3.5 Estructura del request: 400 y 413 (reglas propias) ------------------
section "3.5 Estructura del request (reglas propias 10400/10401)"
check "JSON mal formado -> 400"                 400 -X POST -H "Content-Type: application/json" \
    -d '{"name": "hola",}' "$BASE_URL/catalog/products"

BIGFILE="$(mktemp)"
python3 -c 'import sys; sys.stdout.write("{\"name\": \"" + "a"*500000 + "\"}")' > "$BIGFILE"
check "Body de ~500 KB -> 413"                  413 -X POST -H "Content-Type: application/json" \
    --data-binary @"$BIGFILE" "$BASE_URL/catalog/products"
rm -f "$BIGFILE"

# --- Resumen -----------------------------------------------------------------
echo
if [ "$FAIL" -eq 0 ]; then
    echo -e "${BOLD}${GREEN}Todo OK: $PASS/$TOTAL${NC}"
else
    echo -e "${BOLD}${RED}Fallaron $FAIL de $TOTAL${NC} (pasaron $PASS)"
fi

exit "$FAIL"
