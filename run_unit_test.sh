#!/bin/bash

function run_unit_test() {
    UNIT_TEST="$1"
    if [ -z $UNIT_TEST ]; then
        echo "Usage : $0 <unit_test>"
        exit 1
    fi

    if [ ! -f "src/bin/$UNIT_TEST.rs" ]; then
        echo "$UNIT_TEST does not exist."
        exit 1
    fi

    SHELLCODE="$(cargo run --bin "$UNIT_TEST")"
    CODE=$?
    if [ $CODE != 0 ]; then
        echo "Rust exited with the exit status : $CODE"
        exit 1
    fi

    echo $SHELLCODE | tail -1 | tr -d '\n' | qemu-arm-static ./vuln
    rm -f core
    mv qemu*.core core

    python -m unittest -k "$UNIT_TEST"
}

rm -f qemu*.core

if [ $# == 0 ]; then
    for u in src/bin/*.rs; do
        run_unit_test $(basename -s '.rs' $u)
    done
else
    run_unit_test $1
fi