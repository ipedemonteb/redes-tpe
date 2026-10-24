#!/bin/bash
# 3.4 Inspección de headers: User-Agent de scanner y cookie SESSIONID manipulada.
source "$(dirname "$0")/common.sh"

section "3.4 Inspección de headers"

attack "User-Agent de sqlmap" \
    -A "sqlmap/1.7.2" "$BASE_URL/"
note "El scanner entra sin ningún filtro (200): nada frena el reconocimiento automatizado."

attack "Cookie SESSIONID arbitraria (sin formato UUID)" \
    -b "SESSIONID=victima-123" "$BASE_URL/cart"
note "La app acepta 'victima-123' tal cual: no aparece Set-Cookie en la respuesta."
note "Sin cookie, en cambio, la app asigna un UUID. Un atacante puede fijar o adivinar IDs de sesión."
