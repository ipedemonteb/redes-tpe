#!/bin/bash
# 3.5 Validación de estructura: JSON mal formado y body demasiado grande.
source "$(dirname "$0")/common.sh"

section "3.5 Validación de estructura de la request"

attack "JSON mal formado (coma de más)" \
    -X POST -H "Content-Type: application/json" -d '{"name": "hola",}' \
    "$BASE_URL/catalog/products"
# Los dos casos dan 400: lo que distingue quién respondió es el body (página de nginx del WAF vs. JSON de Catalog).
if [ "$LAST_CODE" = "400" ] && [[ "$LAST_BODY" == *"<center>nginx</center>"* ]]; then
    note "Rechazado en el borde por el WAF (regla propia 10401: el body no es JSON válido)."
else
    note "Llegó al backend: lo rechazó Catalog al intentar parsearlo."
fi

# lastpipe: attack corre en este shell (no en un subshell del pipe), así LAST_CODE queda visible.
shopt -s lastpipe
python3 -c 'print("{\"name\": \"" + "a"*500000 + "\"}")' | \
    attack "Body JSON de ~500 KB" \
        -X POST -H "Content-Type: application/json" --data-binary @- \
        "$BASE_URL/catalog/products"
if [ "$LAST_CODE" = "413" ]; then
    note "Cortado por el WAF (regla propia 10400: el body supera el límite de 128 KB)."
elif [ "$LAST_CODE" = "500" ]; then
    note "El payload llegó al backend sin filtro y lo rompió (500)."
else
    note "El payload llegó al backend sin filtro."
fi
