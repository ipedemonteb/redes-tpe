#!/bin/bash
# 3.2 Inspección de query parameters: SQLi y XSS en ?tag=
source "$(dirname "$0")/common.sh"

section "3.2 Inspección de query parameters"

attack "SQLi en el parámetro tag" \
    "$BASE_URL/catalog?tag=1'%20OR%20'1'='1"
if [ "$LAST_CODE" = "403" ]; then
    note "Bloqueado por el WAF (CRS: regla de SQLi 942xxx)."
else
    note "El payload llegó a Catalog sin filtro."
fi

attack "XSS en el parámetro tag" \
    "$BASE_URL/catalog?tag=%3Cscript%3Ealert(1)%3C/script%3E"
if [ "$LAST_CODE" = "403" ]; then
    note "Bloqueado por el WAF (CRS: regla de XSS 941xxx)."
else
    note "El payload llegó a Catalog sin filtro."
fi

note "Catalog no es explotable (consulta parametrizada; el tag se refleja escapado). El valor"
note "del WAF acá es defensa en profundidad: frena el patrón en el borde ante una dependencia"
note "vulnerable o una regresión futura."
