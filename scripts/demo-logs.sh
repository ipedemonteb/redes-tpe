#!/bin/bash
# Demo de logging y monitoreo del WAF.
# Dispara un mix de trafico (legitimo + los ataques representativos) y despues
# muestra el audit log formateado, para ver como cada request queda registrado
# con su codigo HTTP y las reglas que dispararon.
#
#   ./scripts/demo-logs.sh
#
# Necesita el WAF con el motor en "On" (si no lo esta, avisa y sale). El audit
# log se lee con waf-logs.sh (las ultimas ~20 transacciones).
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost}"
NAMESPACE="edge-security"
DEPLOYMENT="waf"
DIR="$(dirname "$0")"

GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; GRAY='\033[0;90m'; BOLD='\033[1m'; NC='\033[0m'

# --- Chequeo: WAF levantado y en modo On -------------------------------------
if ! kubectl get deploy "$DEPLOYMENT" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "No encuentro el deployment $DEPLOYMENT en $NAMESPACE. ¿Esta levantado el WAF?" >&2
    exit 1
fi

MODE="$(kubectl get deploy "$DEPLOYMENT" -n "$NAMESPACE" \
    -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="MODSEC_RULE_ENGINE")].value}' 2>/dev/null)"
if [ "$MODE" != "On" ]; then
    echo -e "${RED}El WAF esta en modo '${MODE:-?}'.${NC} Para esta demo tiene que estar en On."
    echo "Prendelo con:  ./scripts/waf.sh mode on"
    exit 1
fi

# fire "descripcion" <args de curl...>  -> imprime el codigo HTTP que devolvio
fire() {
    local desc="$1"; shift
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 "$@")
    local col="$GRAY"
    [ "$code" = "200" ] && col="$GREEN"
    [ "$code" -ge 400 ] 2>/dev/null && col="$RED"
    printf "  ${col}%-3s${NC}  %s\n" "$code" "$desc"
}

echo -e "${BOLD}Demo de logging del WAF${NC}  (BASE_URL=$BASE_URL)"
echo
echo -e "${BOLD}${BLUE}── Disparando trafico…${NC}"

# --- Trafico legitimo (200) --------------------------------------------------
fire "Home de la tienda (legitimo)"                 "$BASE_URL/"
fire "Catalogo con tag normal (legitimo)"           "$BASE_URL/catalog?tag=clothing"

# --- Ataques (403) -----------------------------------------------------------
fire "SQL Injection en ?tag"                         "$BASE_URL/catalog?tag=1'%20OR%20'1'='1"
fire "XSS en ?tag"                                   "$BASE_URL/catalog?tag=%3Cscript%3Ealert(1)%3C/script%3E"
fire "Scanner (User-Agent sqlmap)"        -A "sqlmap/1.7.2" "$BASE_URL/"
fire "Path interno desde afuera (/proxy/orders)"     "$BASE_URL/proxy/orders"

echo
echo -e "${BOLD}${BLUE}── Audit log del WAF${NC}  ${GRAY}(ultimas transacciones)${NC}"
echo

# Pequena espera: el log tarda un instante en reflejar las ultimas requests.
sleep 1
bash "$DIR/waf-logs.sh" -n 20
