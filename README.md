# RASGA32

A Rusty fork of the existing project [asga](https://github.com/pratX/asga/) that consists of transforming some arbitrary *arm32* shellcode into its alphanumeric equivalent.

The main pro of this implementation is that the generated shellcode works on modern *aarch64* (ARMv8) machines that are retrocompatible with *arm32*. The original repo will produce a shellcode that will straight up crash every single time because of architecture issues.

Heavily based on the papers :
- [Filter-resistant code injection on ARM](https://www.fort-knox.org/files/armshellcode.pdf) by Yves Younan and his team
- [pratX](https://github.com/pratX/asga/blob/master/docs/BTP_rep.pdf) that describes its own implementation in his original repository.

## Main issue

Those are the problematic instructions that led me to reimplement the code base in Rust :

```
SUBPL rX, pc, rY, ROR rZ      (builder.c / algo2())
RSB rX, rX, #<state.I | 0x30> (builder.c / DecoderLoopBuilder())
```

Those instructions triggers SIGILL on *arm32* binaries that are being executed on modern aarch64 machines,
despite being valid instructions at a first glance.

I found it easier to reimplement his whole code base than trying to modify the latter.

## Summary

Registers $R_{\{i=3,j=5,k=7\}}$ are heavily used to perform operations that could be **not alphanumeric**, as they naturally produce alphanumeric instructions.

- $R_i$ stores a constant integer, randomly generated at start. It is mainly used to set values for other registers.
- $R_j$ is equal to -1 (`0xffffffff`).
- $R_k$ stores the result of operations.

Registers $R_{\{4,6\}}$ can also be used to some extend. The others are impossible to manipulate. The only way to change their values is through `lmul()` function, which actually pumps values from the stack.

`sub`, `add`, `mul` are reimplemented through repeated `xor` operations through $R_{i,j,k}$.

## Goal

As the self-modifying system described in the paper does not work at all on modern *ARMv8* machines, all the main entrypoint does is call `syscall(SYS_read, 0, <address>, <size>` at the end.

## Getting started

Print usage :
```
$ cargo run -- --help
```

### Example

Call `syscall(SYS_read, 0, 0x70776000, 0x200)` :
```
$ cargo run --bin main
eX5PeX5Ps5SPwuWPveVPiP5Rj0ERiPER0PORwgEPuWUPzP5RuWGPugFPugFPuWUPlP5R8P5RuWGPugFPuWUPiP5RipER0pFUsgFPipER0pFUsgFPipER0pFUsgFPsgFPiPERtETPveVPHPMRcIEVcIEVcIEVcIEVcIEV7p4RWp7RcyEVwp4RcyEVpp4RcyEVcIEVlp4Rnp7RcyEVcIEVcIEV0PMRGA5Y4p4R7p7RuTUPiP5Rs4SPvdVPtDTPtDTPtDTPtDTPtDTPj0URAAAOs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SP
```

Change the address and the size arguments in the code.

## Tests

**QEMU is used for the unit testing, as well as the [pwntools](https://github.com/Gallopsled/pwntools) framework (Python3) to read core dumps**.

### QEMU

[To be added](https://letmegooglethat.com/?q=jarvis+how+to+install+qemu)

### Python

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run tests

Supposing that you are on *amd64*, to build `vuln.c` :
```
$ ./build.sh
```

Tests are based on both Rust unittest and Python unittest native frameworks.

To run tests :
```
$ ./run_unit_test.sh [<unit_test>]
```

A *unit test* is named here as `test_XXXX`.
It is implemented by creating a new Rust file of the same name and a new unittest test case in the Python file `tests.py`.
