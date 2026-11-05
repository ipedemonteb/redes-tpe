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
    -d "firstName=<script>alert(1)</script>&lastName=Perez&address1=Calle123&city=CABA&state=CA&zipCode=10000&email=test@itba.edu.ar" \
    "$BASE_URL/checkout"
if [ "$LAST_CODE" = "403" ]; then
    note "Bloqueado por el WAF (CRS: regla de XSS 941xxx sobre ARGS_POST:firstName)."
else
    note "El formulario llegó a la UI sin filtro y se procesó."
fi
attack "Lo que guardó el servicio checkout" \
    "$BASE_URL/proxy/checkout/$SID"
if [ "$LAST_CODE" = "403" ]; then
    note "Bloqueado por la regla 10100 (3.1): /proxy no es accesible desde afuera del clúster."
else
    note "El valor de firstName vuelve tal cual, con las etiquetas <script> intactas: XSS almacenado."
fi

attack "SQLi en el body JSON" \
    -X POST -H "Content-Type: application/json" -d '{"name": "x%'"'"' OR 1=1--"}' \
    "$BASE_URL/catalog/products"
if [ "$LAST_CODE" = "403" ]; then
    note "Bloqueado por el WAF (CRS: regla de SQLi 942xxx sobre ARGS_POST:json.name)."
else
    note "La inyección altera la consulta y devuelve TODOS los productos, no solo los que matchean."
fi

attack "XSS en el body JSON" \
    -X POST -H "Content-Type: application/json" -d '{"name": "<script>alert(1)</script>"}' \
    "$BASE_URL/catalog/products"
if [ "$LAST_CODE" = "403" ]; then
    note "Bloqueado por el WAF (CRS: regla de XSS 941xxx sobre ARGS_POST:json.name)."
else
    note "El <script> vuelve en el HTML sin escapar: se ejecutaría en el navegador (XSS reflejado)."
fi
