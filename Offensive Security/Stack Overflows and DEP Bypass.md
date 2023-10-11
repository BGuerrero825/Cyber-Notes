Requires a compatible CPU and sets the NX (non-executable) bit on sections of data, as opposed to code sections, preventing data injections from being ran.

DEP Options
OptIn : DEP enabled for system processes and custom-defined apps. Default for most client systems.
OptOut : DEP is enabled for everything but specifically exempt apps.
AlwaysOff
AlwaysOn : Default for most server systems.

`LdrpCheckNXCompatibility` in `ntdll.dll` runs some checks to determine if NX should be set (dynamically enabling / disabling DEP), then makes a call to `NtSetInformationProcess` to change NX on the process.

DEP in Notepad Demo:
1. Attach WinDbg to notepad.exe
2. `!vprot eip` : show protections on memory at eip (code section) -> Protect = PAGE_EXECUTE_READ
3. `!vprot esp` : show on memory at esp (data section) -> Protect = PAGE_READWRITE
4. `.load narly` -> `!nmod` : notepad is compiled with *DEP
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

# Return Oriented Programming
The first DEP bypass was return-to-libc on Linux, which evolved into ROP as it is today, which also works on Windows.


### Origins of ROP
Initially Windows DEP could be avoided just by calling `NtSetInformationProcess` through a hijacked JMP ESP and pushing the required arguments on the stack to turn it off. Later Windows used Permanent DEP where any .exe linked with the /NXCOMPAT flag is forced to OptIn with DEP, meaning DEP can't be turned off while the process is running.


### ROP Evolution
ROPs are "borrowed code chunks" near the return of their functions to build more complex functionality, like reading or writing from a memory location.
STACK EXAMPLE IMAGE HERE

Returning into the middle of existing opcodes can also create new instructions, while still terminating in the typical return instruction. Ex. `pop ebp` read one byte later turns into `add al, 5Dh`

We could build a 100% ROP shellcode, but it is much easier to build a ROP stage that then allows execution of traditional shellcode.
Option 1: Allocate memory with VirtualAlloc and write shellcode to it
Option 2: Write shellcode then change its memory page permissions with VirtualProtect
Both of these function addresses will be found in the Import Address Table (IAT) of the target DLL.

The API calls wil require parameters to be pushed, most can be done statically but other arguments must be calculated at runtime using more ROP gadgets.

Option 3: Use WriteProcessMemory to patch the code section at runtime (the .text section) to inject our shellcode and jump to it later.


# Gadget Selection
Finding ROPs manually (like with WinDbg search) would be very tedious, luckily there are automated tools for this.
- Pykd WinDbg Extension
- RP++
- Mona (not covered because it doesn't support Python3 or 64-bit)

### Debugger Automation: Pykd
A Python based WinDbg extension with APIs to automate debugging and crash analysis. Makes finding ROP gadgets a lot easier with the below script.

High level logic:
1. Accept the name of a module (application) and find it in memory
2. For this module, locate all memory pages that are executable
3. For these pages, locate and store memory addreses of all `ret` instructions
4. For these addresses, step back one byte at a time and disassemble to check for valid instructions. Store instructions if they are valid.

Initial set-up:
`from pykd import *`, then run `.load pykd` and `!py C:\Tools\pykd\SCRIPT.py` from WinDbg

...