#!/bin/bash

for go_pkg in \
    "github.com/divergentcodes/jwt-block/cmd/jwt-block" \
    "github.com/divergentcodes/jwt-block/internal/blocklist" \
    "github.com/divergentcodes/jwt-block/internal/build" \
    "github.com/divergentcodes/jwt-block/internal/cache" \
    "github.com/divergentcodes/jwt-block/internal/core" \
    "github.com/divergentcodes/jwt-block/web";
do
    printf "\n\n###############################################################################"
    printf "\n# Generating docs for: $go_pkg"
    printf "\n###############################################################################\n\n"
    go doc -all "$go_pkg"
done
