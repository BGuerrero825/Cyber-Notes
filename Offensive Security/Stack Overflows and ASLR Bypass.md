 ASLR Introduction

Compilers use a preferred base address which set base memory addresses of exe's when loaded. A `/REBASE` flag will allow DLLs to rebase to a different base address if there is a conflict with another DLL.

`/DYNAMICBASE` forces this behavior as a standard, all executables will have a randomized base address. Visual Studio now enables this by default but a lot of older IDE's don't.

Any native DLLs for the basic SYSTEM processes are loaded, randomized, and deconflicted at system boot and do not change until reboot.
Any further DLLs needed by an exe are loaded, randomized, and deconflicted, by the system processes retain their initial address locations.

Entropy: the amount of bits randomized when a base address is chosen. Generally the high 8 bits and low 16 bits remain static.

### ASLR Bypass Theory

Bypass Methods:
- Find modules compiled without ASLR
- Exploit low entropy
- Using a partial override of the lower bits (which aren't randomized) to jump to gadget in the current DLL (whos randomized address is not overwritten).
- Brute Force base addresses
- Leverage an Information Leak