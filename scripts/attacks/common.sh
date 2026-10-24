#!/bin/bash
# Funciones compartidas por los scripts de ataque. No se ejecuta solo: lo cargan los demás con `source`.

BASE_URL="${BASE_URL:-http://localhost}"
BODY_PREVIEW="${BODY_PREVIEW:-300}"   # cuántos caracteres del body mostrar

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; GRAY='\033[0;90m'; BOLD='\033[1m'; NC='\033[0m'

section() {
    echo
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${BLUE} $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════${NC}"
}

note() {
    echo -e "${YELLOW}  ⚠ $1${NC}"
}

# attack "descripción" <argumentos de curl...>
# Ejecuta el request y muestra el comando, el código HTTP y el comienzo del body.
attack() {
    local desc="$1"; shift
    echo
    echo -e "${BOLD}▶ $desc${NC}"
    echo -e "${GRAY}  \$ curl $(printf '%q ' "$@")${NC}"

    local out status body
    out=$(curl -s -i --max-time 15 "$@" | tr -d '\r')
    status=$(printf '%s\n' "$out" | head -1)
    body=$(printf '%s\n' "$out" | sed '1,/^$/d')

    case "$status" in
        "")              echo -e "  ${RED}sin respuesta (timeout o conexión rechazada)${NC}"; return ;;
        *" 2"[0-9][0-9]*) echo -e "  ${GREEN}${status}${NC}" ;;
        *)               echo -e "  ${RED}${status}${NC}" ;;
    esac

    if [ -n "$body" ]; then
        local len=${#body}
        printf '  %s' "$(printf '%s' "$body" | tr '\n' ' ' | head -c "$BODY_PREVIEW")"
        [ "$len" -gt "$BODY_PREVIEW" ] && echo -e " ${GRAY}… (${len} caracteres)${NC}" || echo
    fi
}

# Devuelve el ID de un producto del catálogo, para armar carritos de prueba.
first_product_id() {
    curl -s "$BASE_URL/catalog" | grep -oE 'name="productId" value="[^"]*"' | head -1 | sed -E 's/.*value="([^"]*)".*/\1/'
}

# seed_cart <SESSIONID>: agrega un producto al carrito de esa sesión (por el flujo normal).
seed_cart() {
    local sid="$1" pid
    pid=$(first_product_id)
    curl -s -o /dev/null -b "SESSIONID=$sid" -X POST -d "productId=$pid" "$BASE_URL/cart"
}
