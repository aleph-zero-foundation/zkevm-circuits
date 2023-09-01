#!/usr/bin/env bash

case "$1" in
    "mv")
        sed -i 's/halo2-lookup/pse-mvlookup/g' bus-mapping/Cargo.toml
        sed -i 's/halo2-lookup/pse-mvlookup/g' eth-types/Cargo.toml
        sed -i 's/halo2-lookup/pse-mvlookup/g' gadgets/Cargo.toml
        sed -i 's/halo2-lookup/pse-mvlookup/g' zkevm-circuits/Cargo.toml

        exit 0;;
    "h2")
        sed -i 's/pse-mvlookup/halo2-lookup/g' bus-mapping/Cargo.toml
        sed -i 's/pse-mvlookup/halo2-lookup/g' eth-types/Cargo.toml
        sed -i 's/pse-mvlookup/halo2-lookup/g' gadgets/Cargo.toml
        sed -i 's/pse-mvlookup/halo2-lookup/g' zkevm-circuits/Cargo.toml

        exit 0;;
    *)
        echo "invalid argument: either mv or h2"
        exit 1;;
esac
