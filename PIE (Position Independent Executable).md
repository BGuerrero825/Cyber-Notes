PIE allows code to be placed anywhere in memory, ASLR is the act of actually positioning it randomly.

If a program is compiled without PIE its text and data sections cannot be relocated in memory, however, ASLR can be applied to the stack, heap, and dynamic libraries that it uses, such as libc.

One important caveat to this simple explanation is that Windows can apply ASLR to non-PIE executables by embedding relocation information into the executable, and these relocations are resolved by the linker on the fly when the code is loaded into memory.