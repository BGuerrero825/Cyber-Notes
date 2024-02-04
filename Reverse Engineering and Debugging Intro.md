https://www.youtube.com/watch?v=pgkAmgwIU_4 by Off By One Security

Make a c Hello World program 
`gcc -no-pie -o hello hello.c` : compile without PIE
PIE : Position Independent Executable (ASLR on Linux)
`file hello` : show file info, particularly, that the file is "not stripped" (still has symbols attached)
### Find the main function of a disassembled binary
1. `readelf -a hello | grep Entry` : find entry point of program 
2. `objdump -d -j .text hello | less` : `-d` for disassemble, `-j` to specify section for disassembly
3. find first call instruction
4. Go to mov instruction just above the call (argument push) 
5. This value being pushed is the main function address

`strip hello` : remove symbols from binary

### GDB
`gdb --nx hello` : `-nx` for no extensions
Ctrl-L : clear screen
`info functions`
`disas main`
`disas /r main` : with opcodes
`i r rip`
`break *main+4`
`info breakpoint`
`x/i $rip`
`x/s 0xADDR`
`list` 
`p * (char **) $rsi`
`info reg eflags`
https://en.wikipedia.org/wiki/FLAGS_register

Heap allocations:
`x/4hg ALLOCATION_ADDR - 8` : shows allocation metadata (size, etc.)