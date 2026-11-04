#!/bin/bash
# Guion de la demo en vivo para la exposición. Recorre CADA punto del POC (3.1 a 3.5)
# con el WAF en "On", mostrando para cada uno: un request legítimo (pasa) y el/los
# ataque(s) (se bloquean). Al final, la parte de monitoreo (audit log).
#
# Pensado para una presentación cronometrada: por defecto hace una pausa entre puntos
# para que el orador controle el ritmo (Enter para seguir). No es destructivo: no apaga
# la UI (el /utility/panic se muestra como request bloqueado, que es inofensivo con el WAF).
#
# Uso:
#   ./scripts/demo.sh              # demo completa, con pausas (Enter para avanzar)
#   ./scripts/demo.sh --no-pause   # sin pausas (para ensayar/cronometrar)
#   ./scripts/demo.sh --section 3.2   # solo un punto (3.1 | 3.2 | 3.3 | 3.4 | 3.5 | logs)
#   ./scripts/demo.sh --sin-waf    # agrega, antes de cada punto, el mismo ataque con el WAF apagado
#
# Requiere el WAF levantado. Si el motor no está en "On", ofrece prenderlo.
set -uo pipefail

BASE_URL="${BASE_URL:-http://localhost}"
NAMESPACE="edge-security"
DEPLOYMENT="waf"
DIR="$(dirname "$0")"

GREEN='\033[0;32m'; RED='\033[0;31m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; GRAY='\033[0;90m'; BOLD='\033[1m'; NC='\033[0m'

PAUSE=1
ONLY=""
SHOW_SIN_WAF=0

while [ $# -gt 0 ]; do
    case "$1" in
        --no-pause)  PAUSE=0; shift ;;
        --section)   ONLY="${2:-}"; shift 2 ;;
        --sin-waf)   SHOW_SIN_WAF=1; shift ;;
        -h|--help)   sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) echo "Opción desconocida: $1 (usá -h)"; exit 1 ;;
    esac
done

# --- Helpers -----------------------------------------------------------------

current_mode() {
    kubectl get deploy "$DEPLOYMENT" -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="MODSEC_RULE_ENGINE")].value}' 2>/dev/null
}

title() {
    echo
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE} $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════${NC}"
}

pause() {
    [ "$PAUSE" = "1" ] || return 0
    echo
    read -r -p "$(echo -e "${GRAY}   ⏎ Enter para continuar…${NC}")" _
}

# req "descripción" ESPERADO <args de curl...>
# Dispara el request, imprime el código y si coincide con lo esperado (✅/❌).
req() {
    local desc="$1" expected="$2"; shift 2
    local code col mark
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 "$@")
    if [ "$code" = "$expected" ]; then col="$GREEN"; mark="✅"; else col="$RED"; mark="❌"; fi
    printf "   ${col}%s %-3s${NC} ${GRAY}(esperado %s)${NC}  %s\n" "$mark" "$code" "$expected" "$desc"
}

# Igual que req, pero sin "esperado": solo muestra el código (para la pasada sin WAF).
show() {
    local desc="$1"; shift
    local code col
    code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 20 "$@")
    [ "$code" = "200" ] && col="$GREEN" || col="$YELLOW"
    [ "$code" -ge 400 ] 2>/dev/null && col="$RED"
    printf "   ${col}%-3s${NC}  %s\n" "$code" "$desc"
}

with_waf_off() {
    # Corre un bloque de "show" con el motor apagado y lo restaura a On al terminar.
    [ "$SHOW_SIN_WAF" = "1" ] || return 0
    echo -e "   ${GRAY}— sin WAF (motor Off): el ataque pasa —${NC}"
    bash "$DIR/waf.sh" mode off >/dev/null 2>&1
    "$@"
    bash "$DIR/waf.sh" mode on  >/dev/null 2>&1
    echo -e "   ${GRAY}— con WAF (motor On): —${NC}"
}

SID="11111111-1111-4111-8111-111111111111"

# --- Chequeo inicial: WAF levantado y en On ----------------------------------

if ! kubectl get deploy "$DEPLOYMENT" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "No encuentro el deployment $DEPLOYMENT en $NAMESPACE. ¿Está levantado el WAF?" >&2
    echo "Levantalo con:  kubectl apply -k waf/   (y después ./scripts/waf.sh mode on)" >&2
    exit 1
fi

MODE="$(current_mode)"
if [ "$MODE" != "On" ]; then
    echo -e "${YELLOW}El WAF está en modo '${MODE:-?}'. Esta demo necesita el motor en On.${NC}"
    read -r -p "¿Lo prendo ahora? (Y/n) " ans
    case "${ans:-Y}" in
        [Nn]*) echo "Prendelo con ./scripts/waf.sh mode on y volvé a correr la demo."; exit 1 ;;
        *)     bash "$DIR/waf.sh" mode on ;;
    esac
fi

echo -e "${BOLD}Demo del WAF — The Store${NC}   ${GRAY}(BASE_URL=$BASE_URL, motor=On)${NC}"
[ "$PAUSE" = "1" ] && echo -e "${GRAY}Avanzá con Enter. Cortá con Ctrl-C.${NC}"

# --- 3.1 Control de acceso por path + IP -------------------------------------
sec_31() {
    title "3.1 · Control de acceso por path + IP   (regla propia 10100)"
    echo -e "   ${GRAY}Endpoints internos (datos de clientes, métricas, apagar la UI) solo deben"
    echo -e "   ser alcanzables desde adentro del clúster. Desde afuera → 403.${NC}"
    echo
    with_waf_off _sin_31
    req "Home de la tienda (legítimo)"                 200 "$BASE_URL/"
    req "Órdenes de todos los clientes (/proxy/orders)" 403 "$BASE_URL/proxy/orders"
    req "Métricas internas (/actuator/metrics)"         403 "$BASE_URL/actuator/metrics"
    req "Carrito ajeno por ID — IDOR (/proxy/carts/…)"  403 "$BASE_URL/proxy/carts/victima-123"
    req "Apagar la UI de forma remota (/utility/panic)" 403 "$BASE_URL/utility/panic"
}
_sin_31() {
    show "Órdenes de clientes (/proxy/orders)" "$BASE_URL/proxy/orders"
    show "Métricas internas (/actuator/metrics)" "$BASE_URL/actuator/metrics"
}

# --- 3.2 Query parameters (SQLi / XSS) ---------------------------------------
sec_32() {
    title "3.2 · Inspección de query parameters   (OWASP CRS, anomaly scoring)"
    echo -e "   ${GRAY}SQLi y XSS en ?tag=. El CRS las detecta y la 949110 bloquea por puntaje.${NC}"
    echo
    with_waf_off _sin_32
    req "Catálogo con tag normal (legítimo)"  200 "$BASE_URL/catalog?tag=shoes"
    req "SQLi en ?tag  (942100 → 949110)"     403 "$BASE_URL/catalog?tag=1'%20OR%20'1'='1"
    req "XSS en ?tag   (941xxx → 949110)"     403 "$BASE_URL/catalog?tag=%3Cscript%3Ealert(1)%3C/script%3E"
}
_sin_32() {
    show "SQLi en ?tag (payload entra sin filtro)" "$BASE_URL/catalog?tag=1'%20OR%20'1'='1"
}

# --- 3.3 Body del request (form + JSON) --------------------------------------
sec_33() {
    title "3.3 · Inspección del body   (CRS sobre ARGS_POST: form + JSON)"
    echo -e "   ${GRAY}El ataque viaja en el cuerpo del POST. El WAF bufferiza, parsea según"
    echo -e "   el Content-Type y aplica las mismas reglas 941/942, sea form o JSON.${NC}"
    echo
    req "Alta de producto con nombre normal (legítimo)" 200 -X POST -H "Content-Type: application/json" \
        -d '{"name": "shoes"}' "$BASE_URL/catalog/products"
    req "XSS en form urlencoded (firstName)"            403 -X POST \
        -d "firstName=<script>alert(1)</script>&lastName=Perez" "$BASE_URL/checkout"
    req "SQLi en body JSON (name)"                       403 -X POST -H "Content-Type: application/json" \
        -d '{"name": "x'"'"' OR 1=1--"}' "$BASE_URL/catalog/products"
    req "XSS en body JSON (name)"                        403 -X POST -H "Content-Type: application/json" \
        -d '{"name": "<script>alert(1)</script>"}' "$BASE_URL/catalog/products"
    req "Evasión con Content-Type raro (920420)"         403 -X POST -H "Content-Type: text/plain" \
        -d '{"name": "x'"'"' OR 1=1--"}' "$BASE_URL/catalog/products"
}

# --- 3.4 Headers y cookie ----------------------------------------------------
sec_34() {
    title "3.4 · Inspección de headers   (CRS 913xxx + reglas propias 10300/10301/10302)"
    echo -e "   ${GRAY}Scanner por User-Agent (CRS), formato de la cookie SESSIONID y el header"
    echo -e "   X-Forwarded-Prefix (reglas propias, deny directo).${NC}"
    echo
    req "Sin cookie: la UI asigna una (legítimo)"      200 "$BASE_URL/cart"
    req "Cookie SESSIONID con UUID v4 válido (legítimo)" 200 -b "SESSIONID=$SID" "$BASE_URL/cart"
    req "User-Agent de sqlmap (913100)"                403 -A "sqlmap/1.7.2" "$BASE_URL/"
    req "SESSIONID sin formato UUID (10300)"           403 -b "SESSIONID=victima-123" "$BASE_URL/cart"
    req "Dos cookies SESSIONID — pollution (10301)"    403 \
        -H "Cookie: SESSIONID=$SID; SESSIONID=22222222-2222-4222-8222-222222222222" "$BASE_URL/cart"
    req "Header X-Forwarded-Prefix (10302)"            403 -H "X-Forwarded-Prefix: //evil.com" "$BASE_URL/home"
}

# --- 3.5 Estructura del request (400 / 413) ----------------------------------
sec_35() {
    title "3.5 · Validación de estructura   (reglas propias 10400/10401)"
    echo -e "   ${GRAY}Modelo positivo: se exige forma válida. JSON roto → 400; body enorme → 413.${NC}"
    echo
    req "JSON válido y chico (legítimo)"  200 -X POST -H "Content-Type: application/json" \
        -d '{"name": "shoes"}' "$BASE_URL/catalog/products"
    req "JSON mal formado → 400 (10401)"  400 -X POST -H "Content-Type: application/json" \
        -d '{"name": "hola",}' "$BASE_URL/catalog/products"
    local big; big="$(mktemp)"
    python3 -c 'import sys; sys.stdout.write("{\"name\": \"" + "a"*500000 + "\"}")' > "$big"
    req "Body de ~500 KB → 413 (10400)"   413 -X POST -H "Content-Type: application/json" \
        --data-binary @"$big" "$BASE_URL/catalog/products"
    rm -f "$big"
}

# --- Monitoreo ---------------------------------------------------------------
sec_logs() {
    title "Monitoreo · Audit log del WAF"
    echo -e "   ${GRAY}Cada transacción queda registrada en JSON: IP, método, URI, código y reglas."
    echo -e "   Mostramos las últimas transacciones bloqueadas.${NC}"
    echo
    sleep 1
    bash "$DIR/waf-logs.sh" -n 30 --blocked
    echo
    echo -e "   ${GRAY}En vivo:   ./scripts/waf-logs.sh            (seguí el log mientras atacás)"
    echo -e "   Mix auto:  ./scripts/demo-logs.sh          (dispara tráfico y muestra el log)${NC}"
}

# --- Orquestación ------------------------------------------------------------
run() { "$1"; pause; }

case "$ONLY" in
    "")    run sec_31; run sec_32; run sec_33; run sec_34; run sec_35; sec_logs ;;
    3.1)   sec_31 ;;
    3.2)   sec_32 ;;
    3.3)   sec_33 ;;
    3.4)   sec_34 ;;
    3.5)   sec_35 ;;
    logs)  sec_logs ;;
    *) echo "Sección desconocida: $ONLY (usá 3.1|3.2|3.3|3.4|3.5|logs)"; exit 1 ;;
esac

echo
echo -e "${BOLD}${GREEN}Fin de la demo.${NC}"
