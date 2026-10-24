#!/bin/bash
# Corre todos los ataques de la pre-entrega (3.1 a 3.5) en orden.
DIR="$(dirname "$0")"

for script in "$DIR"/3.*.sh; do
    bash "$script"
done
echo
