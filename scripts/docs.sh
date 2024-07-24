#!/bin/bash

for go_pkg in \
    "github.com/divergentcodes/jwtblock/cmd/jwtblock" \
    "github.com/divergentcodes/jwtblock/internal/blocklist" \
    "github.com/divergentcodes/jwtblock/internal/build" \
    "github.com/divergentcodes/jwtblock/internal/cache" \
    "github.com/divergentcodes/jwtblock/internal/core" \
    "github.com/divergentcodes/jwtblock/web";
do
    printf "\n\n###############################################################################"
    printf "\n# Generating docs for: $go_pkg"
    printf "\n###############################################################################\n\n"
    go doc -all "$go_pkg"
done
