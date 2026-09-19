#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/mman.h>

int main() {
    void (*address)() = (void*)0x70776000;
    void (*shellcode)() = mmap(
        address,
        0x1000,
        PROT_READ | PROT_WRITE | PROT_EXEC,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    read(0, address, 0x1000);
    address();
    return 0;
}