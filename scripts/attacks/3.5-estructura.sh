#!/bin/bash
# 3.5 Validación de estructura: JSON mal formado y body demasiado grande.
source "$(dirname "$0")/common.sh"

section "3.5 Validación de estructura de la request"

note "POST /catalog/products todavía no existe: se crea en el paso 3"
attack "JSON mal formado (coma de más)" \
    -X POST -H "Content-Type: application/json" -d '{"name": "hola",}' \
    "$BASE_URL/catalog/products"

python3 -c 'print("{\"name\": \"" + "a"*500000 + "\"}")' | \
    attack "Body JSON de ~500 KB" \
        -X POST -H "Content-Type: application/json" --data-binary @- \
        "$BASE_URL/catalog/products"
