#!/bin/bash
# Visor del audit log del WAF (ModSecurity), una línea legible por transacción.
#
#   ./scripts/waf-logs.sh              # sigue el log en vivo (Ctrl-C para salir)
#   ./scripts/waf-logs.sh -n 20        # muestra las últimas ~20 transacciones y sale
#   ./scripts/waf-logs.sh --blocked    # solo las bloqueadas (código >= 400)
#   ./scripts/waf-logs.sh -n 50 --blocked
#
# El WAF emite el audit log en JSON a stdout (MODSEC_AUDIT_ENGINE=On,
# MODSEC_AUDIT_LOG_FORMAT=JSON). Este script toma esas líneas, las parsea con jq
# y las imprime como:
#   HH:MM:SS  client_ip  METHOD /uri  CODE  [reglas]  mensaje
set -euo pipefail

NAMESPACE="edge-security"
DEPLOYMENT="waf"

FOLLOW=1
TAIL=200
ONLY_BLOCKED=0

while [ $# -gt 0 ]; do
    case "$1" in
        -n|--tail)   FOLLOW=0; TAIL="${2:-50}"; shift 2 ;;
        -f|--follow) FOLLOW=1; shift ;;
        --blocked)   ONLY_BLOCKED=1; shift ;;
        -h|--help)
            sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
            exit 0 ;;
        *) echo "Opción desconocida: $1 (usá -h)"; exit 1 ;;
    esac
done

# jq: de cada línea de audit (un objeto {"transaction":...}) arma una fila TSV.
JQ_PROG='
  select(.transaction? != null)
  | .transaction as $t
  | (($t.time_stamp // "") | [scan("[0-9]{2}:[0-9]{2}:[0-9]{2}")] | (.[0] // "--:--:--")) as $time
  | ($t.messages // []) as $m
  | ([$m[].details.ruleId] | map(select(. != null)) | unique) as $ids
  | ([$m[].message] | map(select(. != null))) as $allmsg
  | (($allmsg | map(select(test("Anomaly Score") | not)) | .[0]) // $allmsg[0] // "") as $msg
  | [ $time,
      ($t.client_ip // "-"),
      (($t.request.method // "-") + " " + ($t.request.uri // "-")),
      ($t.response.http_code // 0 | tostring),
      ($ids | join(",")),
      $msg
    ] | @tsv
'

format() {
    # encabezado
    printf '%-8s  %-13s  %-42s  %-4s  %-20s  %s\n' \
        "HORA" "CLIENTE" "REQUEST" "CODE" "REGLAS" "MENSAJE"
    printf '%s\n' "────────────────────────────────────────────────────────────────────────────────────────────────────────────"

    local time ip req code rules msg col reqs rulf
    while IFS=$'\t' read -r time ip req code rules msg; do
        # filtro opcional: solo bloqueadas
        if [ "$ONLY_BLOCKED" = "1" ]; then
            case "$code" in ''|*[!0-9]*) continue ;; esac
            [ "$code" -lt 400 ] && continue
        fi
        # color por código
        if   [ "$code" = "200" ];                 then col='\033[0;32m'   # verde
        elif [ "$code" -ge 400 ] 2>/dev/null;     then col='\033[0;31m'   # rojo
        else                                           col='\033[1;33m'   # amarillo
        fi
        reqs="$req"
        [ ${#reqs} -gt 42 ] && reqs="${reqs:0:41}…"
        rulf=""; [ -n "$rules" ] && rulf="[$rules]"
        printf '%-8s  %-13s  \033[0;37m%-42s\033[0m  %b%-4s\033[0m  %-20s  %s\n' \
            "$time" "$ip" "$reqs" "$col" "$code" "$rulf" "$msg"
    done
}

if ! kubectl get deploy "$DEPLOYMENT" -n "$NAMESPACE" >/dev/null 2>&1; then
    echo "No encuentro el deployment $DEPLOYMENT en el namespace $NAMESPACE." >&2
    echo "¿Está levantado el WAF? (kubectl get pods -n $NAMESPACE)" >&2
    exit 1
fi

if [ "$FOLLOW" = "1" ]; then
    echo "Siguiendo el audit log del WAF en vivo (Ctrl-C para salir)…"
    kubectl logs -f --tail=10 -n "$NAMESPACE" "deploy/$DEPLOYMENT" \
        | grep --line-buffered '^{"transaction"' \
        | jq -rc --unbuffered "$JQ_PROG" \
        | format
else
    kubectl logs --tail="$TAIL" -n "$NAMESPACE" "deploy/$DEPLOYMENT" \
        | grep '^{"transaction"' \
        | jq -rc "$JQ_PROG" \
        | format
fi
