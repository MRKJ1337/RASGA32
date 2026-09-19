#!/bin/bash

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

echo $SHELLCODE | tail -1 | tr -d '\n' | qemu-arm-static -g 1234 ./vuln &

cat > debug.gdb <<EOF
b *0x000103f0
target extended-remote 127.0.0.1:1234

context --off stack
context --off backtrace
EOF

gdb -x debug.gdb