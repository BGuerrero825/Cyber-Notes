F6 - attach to process
This will pause execution flow by overwriting the current instruction in memory with the INT 3 assembly instruction.
`.hh` : manual && http://windbg.info/doc/1-common-cmds.html


# Intro

### Symbol Files (.pdb)
allow WinDbg to reference internal functions, vars, structs, etc. using names instead of addresses. Can be configured to fetch symbol files for native Windows executables and libraries from the Microsoft symbol store. 
File -> Symbol FIle Path
`C:\symbols` : a common symbol path
Requires internet connection to download symbols for loaded modules
`.reload` or `reload /f` to force reload of symbol paths
`.symopt- 100` to enable resolution of unqualified symbols (symbols not mapped in the current programs memory)

### Unassemble Memory
display assembly translation of specified program code in memory
`u ADDRESS|ADDRESS_RANGE` : if no argument, will begin from the EIP
`u kernel32!GetCurrentThread` : given a function symbol, resolves to associated address

### Reading from Memory
`db REGISTER|ADDRESS|SYMBOL_NAME` : display bytes
`dw ...` : display word (2 bytes) | `dW ...` : print with ascii
`dd ...` : display double words (4 bytes)
`dq ...` : (8 bytes) | `dc ...` : print with ascii
add `L` and number to only print X amount of bytes
`dd poi(REGISTER)` : get data from register pointer address
`da ...` : display ASCII, 48 characters per line, stops at null byte or end of range
`du ...` : display Unicode

### Dump Structures from Memory
structures can be hard to decipher once compiled to binary
`dt STRUCT` : dump structure type given its name, struct needs to be provided by a loaded symbol file
ex. `dt ntdll!_TEB` : Thread Environment Block struct
`dt -r ntdll!_TEB @$teb` : recursively display nested structures from the $teb pseudo register (instance of struct)
`dt -r ntdll!_TEB @$teb ThreadLocalStoragePointer` : dump specific structure type only
`?? sizeof(ntdll!_TEB)` : return size of the bytes in a struct

### Writing to Memory
`e...` : edit command
`ed esp 41414141` : write to register address as hex
`ea` : edit as ascii
`eu` : edit as unicode

example: shellcode that writes a file to disk, the path needs to be supplied as bytecode. Use WinDbg to write the path directly to memory, then from the exploit code `db` the bytes and copy into the shellcode

### Searching Memory Space
`s...` : search memory
`s -d 0 L?80000000 41414141` : search for dword 41414141, searching from 0 and through all memory ?80000000 (entire process memory space)
`s -a 0 L?80000000 "This program cannot be run in DOS mode"` : search program for ascii string
`-b|w|d|q|a|u` : print as bytes (default), word, dword, qword, ASCII, or unicode
`-[1]...` : Only show address of search matches. Use in a .foreach where output is piped

### Inspect and Edit Registers
`r` : inspect all registers 
`r REGISTER`
`r ecx=41414141` : edit register
`.formats REGISTER` : show register in different numeric formats

### Inspect Callstack
`k` : dump callstack 

# Breakpoints
Software breakpoints : directly controlled by debugger
Hardware breakpoints : controlled by the processor but set through the debugger

### Software Breakpoints
temporarily replaces the opcode location with an INT 3 instruction. We can set as many software breakpoints as needed.
`bp ...` : set breakpoint
`bp kernel32!WriteFile` : set breakpoint when changes are saved to a file (Windows WriteFile API)
`bl` : list breakpoints
`g` : resume execution
`bd # || be #` : disable or enable breakpoint based on number
`bc # || bc *` : clear breakpoint number or clear all breakpoints

### Unresolved Function Breakpoint
`bu` : resolve breakpoint on module load, break on specific function call
`lm` : list module `lm m ole32`
`bu ole32!WriteStringStream`

### Breakpoint-Based Actions
`bp kernel32!WriteFile ".printf \"Bytes Written: %p\", poi(esp + 0x0C);.echo;g"` : print the number of bytes written when breakpoint is hit
	`.echo` is needed to display output to WinDbg window
	`g` resumes program after completion 
	we know to use `0x0C` by inspecting the WriteFile Prototype (Google?)
`bp kernel32!WriteFile ".if(poi(esp + 0x0C) != 4) {gc} .else {.printf \"4 bytes written\";.echo;}"` :  print statement if 4 bytes were written at breakpoint
	`gc` resume from conditional breakpoint

### Hardware Breakpoints
Uses the processors debug registers, can stop on particular accesses (read write execute) on targeted memory locations.
Limit to 4 debug registers
`ba ...` : set hardware breakpoint
`ba r|w|e 1 kernel32!WriteFile` : break on 1 byte read/write/execute at WriteFile
Ex. 
- Write "w00tw00t" to notepad.exe, save and close. Re-open, attach WinDbg. 
- `s -u 0x0 L?80000000 w00tw00t`, find memory address of the string
- `ba w 2 03b2c768` : set hardware breakpoint on memory address of the first character
- `g`
- In notepad, replace string with "a", this triggers breakpoint, edi register points to the string
- `du edi` > "w00tw00t" 

### Stepping Through Code
`p` : step over instruction
`t` : step into instruction (nest into a call)
`pt` : step to next return (jump to end of function)
`ph` : step to next branch

### List Modules and Symbols
`lm` : displays loaded modules
`.reload /f` : force reload modules (module names wont display on a fresh instance of a process)

> When a PDB file is not available for a module, WinDbg will default to the export symbols mode, attempting to gather the names of symbols through the Export Directory Table.

`lm m kernel*` : list all modules starting with string "kernel"
`x kernelbase!CreateProc*` : examine symbol, starting with string*

### Calculations
`?` : evaluate expression
`? 77269bc0 - 77231430` : calculate address difference
	add, sub, mult, div, mod, exp, bit shift (>>, <<)
By default displays in hex. Prefixes:
`0n` : input as decimal format
`0y` : input as binary format
`.formats 41414141` : show value in all formats

### Pseudo Registers
variables defined by WinDbg
User defined variables : `$t0` - `$t19`
Most variables are predefined, like `$teb`
`@` : denotes that the value is a psuedo register instead of a symbol
```
r @$t0 = (41414141 - 414141) * 0n10  # perform calculation, then store to register
r @$t0 # print register
? @$t0 >> 8 # perform a bitshift of 8
```

## Other & Extensions
`!exchain` : extension to list the current thread exception handler chain
narly : `.load narly` -> `!nmod` : lists all loaded modules and their memory protections (SafeSEH, GS, DEP, and ASL)
`!address ADDRESS` : extension that shows in what section of memory a given address resides
`!pcr` and `!prcb` : view the contents of the KPCR and KPRCB