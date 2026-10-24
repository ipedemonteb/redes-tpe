#!/bin/bash
# 3.5 Validación de estructura: JSON mal formado y body demasiado grande.
source "$(dirname "$0")/common.sh"

section "3.5 Validación de estructura de la request"

attack "JSON mal formado (coma de más)" \
    -X POST -H "Content-Type: application/json" -d '{"name": "hola",}' \
    "$BASE_URL/catalog/products"
note "Sin WAF, Catalog intenta parsear y responde 400. Con WAF, el 400 lo da el borde (REQBODY_ERROR)."

python3 -c 'print("{\"name\": \"" + "a"*500000 + "\"}")' | \
    attack "Body JSON de ~500 KB" \
        -X POST -H "Content-Type: application/json" --data-binary @- \
        "$BASE_URL/catalog/products"
note "Sin WAF, el payload llega al backend y lo rompe (500). Con WAF, se corta en el borde con 413."
