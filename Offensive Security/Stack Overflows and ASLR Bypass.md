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
step into debug dispatch to find path to the basic block we need
lots of branching paths
theres a repeating pattern in the leading blocks
	a call to strbytelen (wraps strlen) and strnicmp (strcmp)
the first block checks length and compares against "help"
set a bp on strnicmp
dd esp L3 the args
2nd arg is "help"
3rd arg (max size) is 4
1st arg is pointer to buff of A's
since the first 4 chars of the A's dont match "help", the function returns a non-z value and a branch is taken to a new cmp
new cmp is the same but with "DumpMemoryPools"
skipping to block just above we see the same cmp's but with "SymbolOperation"
update POC with psCommandBuffer beginning with "SymbolOperation"
- set new bp on the string compare call for the string above
- breakpoint triggered
- da poi(esp) shows our string whihc passes the check
- bp on symgetsymfromname
- The desired branch is taken, and the call is reached
- PROTOYPE for SymGetSymFromName
	- HANDLE  hProcess,
	- PCSTR Name : pointer to symbol name to be resolved as a null terminated string
	- IMAGEHLP_SYMBOL Symbol
 - value of Name in the current POC is the string A's
 - Symbol is a pointer to a struct that is populated by the SymGetSym
 - We specifically want to get the Address field of this populated struct
	 - This gives the base address of the specified symbol Name
 - Update script to look for address of WriteProcessMemory, `buf += b'SymbolOperationWriteProcessMemory'`
 - bp at DebugDispatch call, run script
 - `da poi(esp+4)` shows WriteProcessMemory, our input
 - `dd esp+8 L1` -> `dds PREV+4 L1` shows 0000's where the returned address will go
 - `p` to step over the API call
- `dds PREV+4 L1` shows address of WriteProcessMemory !!
- Now we just need a way to retrieve this info over the network

### Symbol Address Retrieval
- It makes sense that this functionality is intended to return some info back to the user
- Continue reversing to find a code path that returns the SymGetSym info
- D: Inspect return val of SymGetSym as this affects the branch path
- `pt` to see return logic
- S: the next block performs a bunch of string manipulations
- the output from the sprintf calls are stored at an offset from ebp
- interested in the final string,
- find value of arg_0 (which is the offset from ebp used) up in the function declaration
- D: `dd ebp+8 L1` shows a pointer the string about to be manipulated
- bp at the end of this function
- `da PREV` shows the new content of the string pointer, which has the requested function address and other debug info
- After this, we drop back into Exec_Command from DebugDispatch
- there is cmp check for eax (return value of DebugDispatch) in which the jump is not taken (eax = 1)
- S: next block is a mass converge of many conditionals, continue dynamic exec until this point (D: vs S: for dynamic vs static analysis)
- D+S: We dont control the values in these checks, just follow the cmps and jumps and analyze whats happening
- S: stop when seeing a call to GetConnectedIpPort
- There are `lea` instructions just before the call, which usually signifies that a pointer to a previous call's return value is being loaded (and then being passed as an arg to this call)
- D: bp at the call to IpPort
- dump memory of the two addresses before the call `dd ebp-12550 L1` and `dd ebp-61bc L1`
- `p` then dump memory after the call, see above step. They are now populated
- What are these values and how do we interpret them? 
- Guessing from the call function name `GetConnectedIpPort` we can assume some association to a socket connection, which usually uses win socket `connect`
	- PROTOTYPE for WSAAPI connect
	- theres a sockaddr substructure referred to by `*name` 
	- PROTOTYPE for sockaddr_in
	- sockaddr_in's ip address is an 'in_addr' struct and its port is an u_short (unsigned word)
	- each octet of the IP address is a single byte of the (2nd) dword returned by GetConnectedIpPort
- translate 0276a8c0 to IP with `? c0; ? a8; ? 76; ? 02;`
- translate 000032cc to decimal `? 32cc`
- open cmd as admin, run netstat -anbp tcp to see current tcp connections and find the above network connection
- D+S: Following the flow we eventually see a block with a call to IF_Buffer_Send
- bp on IF_Buffer_Send
- dump contents of function arg with da poi(esp)
- the debug string with WriteProcessMemory's address is the passed arg :)
- Skip inspecting this function and modify script and see if we can catch this data
- `response = s.recv(1024) // print(response)
- Run the script and catch the address for WriteProcessMemory
- Update script to parse for "Address is" and only print the address value, for easy passing into future script functionality, create case for null as well
	- `def parse_response(response): ...`
	- `response_address = parse_response(response) // print(str(hex(response_address)))`
- And make sure that works


--- 
# Expanding the Exploit (ASLR Bypass)

Previously we were able to retrieve an address to `WriteProcessMemory` which also gave a pointer to `kernel32.dll`. However, every monthly Windows update will change the offsets of symbols within this module, breaking any ROP gadgets used by the exploit. To make this exploit more resilient, we can leak the baked in IBM modules instead and build ROP gadgets from those, meaning that the exploit will only be dependent on the version of FastBackServer (vs the version of Windows)

### Leaking an IBM Module
List loaded IBM modules and their locations. From there select a suitable module to pass to the information leak vulnerability to determine its runtime address and start building the ROP chain.

- D: `lm f`, shows 10 IBM modules + the FastBackServer exe
- Can't use any that start with 0x00
- Arbitrarily chose `libeay32IBM2019.dll`
- Find filepath and transfer .dll file to Kali box for IDA analysis
- S: Go to export table, take arbitrary function and find its offset from the base address of the module
	- In this case `N98E_CRYPTO_get_net_lockid`
 - Run the script looking for this symbol: `symbol = b"SYMBOL" + b"\x00 // buf += symbol + ... // #way later // libeay32IBM019_base = response_address - 0x14E0`
- Run script and ensure it gets the base address
### Avoiding Bad Characters
The previous list of bad characters found in the DEP exploit still apply here, and there is a bad one in the return base address. Use ProcMon to verify that the FastBack WatchDog is restarting the FastBackServer after a crash. Then, rerun the script to get the new base address after being randomized by ASLR and check if it still contains a bad character.

ProcMon : Process Monitor

- Bad chars: 0x00, 0x09, 0x0a, 0x0c, 0x0d, 0x20
- We are leveraging the same scanf vulnerability so the bad chars still apply
- If the returned base address has a bad char we cant use it
- FastBack WatchDog should restart FastBack on crash
- Run ProcMon.exe as admin, which can monitor process creation
	- Filter > Filter
	- Filter Rule: Operation | contains | Process // for Process Start and Process Exit
	- Add > Apply
- Create a crash by attaching WinDbg then closing WinDbg
- Watch the process restart then rerun the script to get a new base address
- If no bad char then its good to go, otherwise repeat process
  

--- 
# WriteProcessMemory DEP Bypass

In the previous DEP bypass VirtualAlloc was used to modify the protections of the stack where the shellcode lives. Here a new technique is used via WriteProcessMemory to copy our shellcode from the stack into an allocated module's code page. Specifically, copy the shellcode into `libeay32IBM019` which is already executable. Typically a code page is not writeable, but WriteProcessMemory will take care of this.

### WriteProcessMemory
```
BOOL WriteProcessMemory(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T *lpNumberOfBytesWritten
)
```
- hProcess is a handle to the desired process, in this case -1 will get the current process. The intent is to perform a copy operations in the current process
- lpBaseAddress is the absolute memory address in the code section where the new code will be written. The exploit should avoid overwriting existing code.
	- Compiled code is page-aligned. When the opcodes don't use up the whole page the rest of the page will be nulled (0x00's). This can be used to find where the "code cave" (space for the new injected code) begins

- D: Attach to FastBack, pause exec
- Offset to PE header is located at offset 0x3C from the MZ header
	- [[Portable Executable (PE)]]
	- dd libeay32IBM019 + 3c L1
	- PE Header Offset: 00000108
- Offset to code section is 0x2C from PE Header
	- dd libeay32IBM019 +0x108 + 2c
	- Code Segment Offset: 00001000 (from base addr)
- ? libeay32IBM019 + 1000 = 031c1000
- !address 032c1000
- see End Address: 03250300
- subtract an arbitrary large space (400) from End Address to determine if theres space to write a shellcode in the code cave
- see a bunch of 00's? Then this is unused space we can use
- Protections are still PAGE_EXECUTE_READ
- Find the offset into the module where the code cave starts
	- 03253000 - 400 - libeay32IBM019 = 00092c00
	- this has a null byte, but we can just use 092c04 instead
- So lpBaseAddress will be libeay32IBM019 + 092c04

- lpBuffer is the source of the write, so it must take the stack address of the overflowed shellcode
- nSize is the size of the shellcode
- `*lpNumberOfBytesWritten` is a location where the function will report the number of bytes written 
	- Use an address in the data section of `libeay32IBM019` since it wont have to be gathered at runtime
- !dh -a libeay32IBM019, to dump data section and header info
	- Look for: SECTION HEADER #4 // .data name // F018 virtual size // D5000 virtual address
	- size is 0xf018 and offset is 0x5000
- Again, this is page aligned and any unused space is nulled, so find the "data cave" using the previous info
- ? libeay32IBM019 + d5000 + f018 + 4 = 032a401c
- dd 032a401c, shows a bunch of null bytes
- !vprot ADDR, shows the section is set as PAGE_READWRITE
- ? ADDR - libeay32IBM019, shows offset of data writeable section from base address

Make the API call with ROP
- Set up the python script to the point where it triggers the scanf buffer overflow
- ROP Skeleton for WriteProcessMemory goes in psCommandBuffer (PUT CODE HERE)
	- WriteProcessMemory address is known (will be pointed to by the eip overwrite)
	- shellcode return address (rop chain returns here)
	- (start args) Handle is -1
	- base address is module + code cave offset
	- buffer (from) address is not know yet
	- 

shellcode stuff

test shellcode

see execution of shellcode









 




