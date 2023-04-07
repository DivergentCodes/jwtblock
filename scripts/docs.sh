#!/bin/bash

for go_pkg in \
    "divergent.codes/jwt-block/cmd/jwt-block" \
    "divergent.codes/jwt-block/internal/blocklist" \
    "divergent.codes/jwt-block/internal/build" \
    "divergent.codes/jwt-block/internal/cache" \
    "divergent.codes/jwt-block/internal/core" \
    "divergent.codes/jwt-block/web";
do
    printf "\n\n###############################################################################"
    printf "\n# Generating docs for: $go_pkg"
    printf "\n###############################################################################\n\n"
    go doc -all "$go_pkg"
done
