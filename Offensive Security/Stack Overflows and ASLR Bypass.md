 ASLR Introduction

Compilers use a preferred base address which set base memory addresses of exe's when loaded. A `/REBASE` flag will allow DLLs to rebase to a different base address if there is a conflict with another DLL.

`/DYNAMICBASE` forces this behavior as a standard, all executables will have a randomized base address. Visual Studio now enables this by default but a lot of older IDE's don't.

Any native DLLs for the basic SYSTEM processes are loaded, randomized, and deconflicted at system boot and do not change until reboot.
Any further DLLs needed by an exe are loaded, randomized, and deconflicted, by the system processes retain their initial address locations.

Entropy: the amount of bits randomized when a base address is chosen. Generally the high 8 bits and low 16 bits remain static.

### ASLR Bypass Theory

There are multiple ways to counter a module protected by ASLR.

Modules Compiled without ASLR:
- Use WinDbg `narly`
Check for /DYNAMICBASE, narly looking for `*ASLR`

Exploit Low Entropy:
- Lower 16 bits of a module are not randomized, so a partial override into the lower bits of an ASLR module will still redirect reliably 

Brute Force:
- Realistic in 32-bit where only 8-bits of entropy are provided, app must not crash on invalid ROPs (or auto-restarts after crash)

Information Leaks:
- Leverages a feature (or another exploit) which gives information about a modules address space.
- This is the most modern and practical methodology

