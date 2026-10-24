#!/bin/bash
# 3.2 Inspección de query parameters: SQLi y XSS en ?tag=
source "$(dirname "$0")/common.sh"

section "3.2 Inspección de query parameters"

attack "SQLi en el parámetro tag" \
    "$BASE_URL/catalog?tag=1'%20OR%20'1'='1"

attack "XSS en el parámetro tag" \
    "$BASE_URL/catalog?tag=%3Cscript%3Ealert(1)%3C/script%3E"

note "Catalog no es explotable (consulta parametrizada; el tag se refleja escapado), pero el"
note "payload llega a la app sin filtro. El valor del WAF acá es defensa en profundidad:"
note "frena el patrón en el borde ante una dependencia vulnerable o una regresión futura."
