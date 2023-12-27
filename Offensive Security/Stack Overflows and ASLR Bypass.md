[[#ASLR Introduction]]
[[#Finding Information Leaks]]
	[[#FXCLI_DebugDispatch]]
	[[#Arbitrary Symbol Resolution]]
[[#Expanding the Exploit (ASLR Bypass)]]
 
---
# ASLR Introduction
Compilers on Windows take a *preferred base* address parameter which sets a base memory addresses of an executable when loaded. 

`/REBASE`: compiler flag that allow DLLs to rebase to a different base address within a process if there is a conflict with another DLL.

`/DYNAMICBASE`: is "ASLR". Forces rebase behavior as a standard, all executables will have a randomized base address. Visual Studio now enables this by default but a lot of older IDE's don't.

Native DLLs for the basic SYSTEM processes are loaded, randomized, and deconflicted at system boot but do not change until reboot.
Any further DLLs needed by an exe are loaded, randomized, and deconflicted, but a previously loaded SYSTEM DLLs retain their initial base addresses.

32-bit ASLR with standard entropy only randomizes 8 bits of an address
STATIC      | RANDOM | STATIC
00000000 | 11111111 | 00000000 00000000
Entropy: the amount of bits randomized when a base address is chosen. Generally the high 8 bits and low 16 bits remain static.
64-bit ASLR randomizes up to 19 bits

### ASLR Bypass Theory
There are 4 primary ways to bypass ASLR protections.

Modules Compiled without ASLR:
- Check for the `/DYNAMICBASE` flag in other modules, shown as `*ASLR` in WinDbg narly

Exploit Low Entropy:
- Lower 16 bits of a module are not randomized, so a partial override into the lower bits of an ASLR module will still redirect reliably 
- Limited to a gadget size of 1 which may work if module compiled without DEP

Brute Force:
- Realistic in 32-bit where only 8-bits of entropy are provided, app must not crash on invalid ROPs (or must auto-restart after crash)

Information Leaks:
- Leverages a feature (or another exploit) which gives information about a modules address space.
- This is the most modern and practical methodology

### Windows Defender Exploit Guard
See [[Stack Overflows and DEP Bypass#Windows Defender Exploit Guard (WDEG)]] enabling ASLR in addition to DEP

Restart FastbackServer and reattach WinDbg, each time running `lm m csftpav6` to see the base address changing on each run 


---
# Finding Information Leaks
Usually this process requires thorough reverse engineering of a programs code paths. 
But we can lean on known Win32APIs info leaks if they are imported by the program.
One example is `Dbghelp.dll` which resolve function addresses from symbol names.

### FXCLI_DebugDispatch
Start an IDA session on FastBackServer.exe to investigate Win32 APIs.
One specifically interesting API found in the Imports tab is `SymGetSymFromName`, which is loaded from `dbghelp` and may cause an info leak, but we don't know how it's accessed yet.

Reverse engineer `SymGetSymFromName` call stack:
1. Double click the API to go to the entry inside the .idata section
2. Cross-reference the API name (click name and press x) 
	- Both references come from `FXCLI_DebugDispatch`
3. Click into and navigate `DebugDispatch` graph to the function declaration (top left) and cross reference again on the function name.
	- This reference comes from `Exec_Command` which we know manages network input logic
4. Click into the reference to see where the function is called from within `Exec_Command`

Craft Input to reach `SymGetSymFromName` call:
1. Move up basic blocks to find `cmp` instructions which steer code flow. 
	- Only one block up is a comparison to the opcode offset of the input (with knowledge from previous reverse engineering) against 0x2000
2. Update the python script with the new opcode
3. Change the psCommandBuffer to send A's, B's, and C's for each of the 3 buffers (lengths specified in psAgentCommand as before)
4. Static Dynamic Analysis with a `bp` at the opcode comparison instruction
	- WinDbg cant randomize the base address so static values will work for breakpoints
5. Run the program, stopping at the opcode check and confirming it works
6. `pa` (step to address) on the call to `DebugDispatch` confirming it reached there
7. `dd esp L3` to dump the arguments to this function
	- The values are pointers, dumping the 2nd shows a list of A's meaning it points to the input network buffer

### Arbitrary Symbol Resolution



--- 
# Expanding the Exploit (ASLR Bypass)