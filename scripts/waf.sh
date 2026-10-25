#!/bin/bash
# Controla el modo del motor de ModSecurity en el WAF.
#   ./scripts/waf.sh mode on|detect|off
#   ./scripts/waf.sh status
set -e

NAMESPACE="edge-security"
DEPLOYMENT="waf"

current_mode() {
    kubectl get deploy "$DEPLOYMENT" -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.containers[0].env[?(@.name=="MODSEC_RULE_ENGINE")].value}'
}

case "$1" in
    mode)
        case "$2" in
            on)     value="On" ;;
            detect) value="DetectionOnly" ;;
            off)    value="Off" ;;
            *) echo "Uso: $0 mode on|detect|off"; exit 1 ;;
        esac
        if [ "$(current_mode)" = "$value" ]; then
            echo "El WAF ya está en modo $value"
            exit 0
        fi
        kubectl set env "deploy/$DEPLOYMENT" -n "$NAMESPACE" MODSEC_RULE_ENGINE="$value"
        kubectl rollout status "deploy/$DEPLOYMENT" -n "$NAMESPACE" --timeout=60s
        for _ in $(seq 1 60); do
            kubectl get pods -n "$NAMESPACE" -l app=waf --no-headers 2>/dev/null | grep -q Terminating || break
            sleep 1
        done
        echo "WAF en modo $value"
        ;;
    status)
        echo "MODSEC_RULE_ENGINE=$(current_mode)"
        ;;
    *)
        echo "Uso: $0 mode on|detect|off | status"
        exit 1
        ;;
esac
