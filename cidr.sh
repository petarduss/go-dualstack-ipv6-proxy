#!/bin/bash
PREFIX="2a14:7584:44b3:0"
INTERFACE="eth0"

for i in $(seq 0 1023); do
    if [[ "$i" -eq 1 || "$i" -eq 2 ]]; then
        continue
    fi

    hex_addr=$(printf '%x' $i)
    ADDR="${PREFIX}::${hex_addr}/128"
    sudo ip -6 addr add "$ADDR" dev "$INTERFACE"
done