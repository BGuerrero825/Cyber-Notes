x86 calling conventions define:
- How arguments are passed to a function.
- Which registers the callee must preserve for the caller.
- How the stack frame needs to be prepared before the call.
- How the stack frame needs to be restored after the call.

> **Win32 API** uses the `__stdcall` while C runtime uses the `__cdecl` calling convention
> Both: callee pushes parameters on the stack in reverse order
> stdcall: stack is cleaned by callee
> cdecl: stack is cleaned by caller
> **For any calling convention** on a 32-bit system, the EAX, EDX, and ECX registers are considered volatile (likely to be destroyed during a function call)


# The System Call Problem
syscalls are a set of functions that allow kernel space functionality (I/O, thread sync, sockets, etc.) to be called from user space. Shellcodes lean heavily on use syscall functionality. However, Windows kernel-level functions are identified by syscall numbers that tend to change between releases (Linux, in contrast, is static). In addition to this, the Windows syscall interface doesn't expose all kernel level functionality, such as sockets. 

Therefore, syscalls can't be used for portability and full functionality. We are instead forced to use the Windows Native API, which is exported via DLLs and exposed to user mode via ntdll.dll. 

kernel32.dll exposes functions that can load libraries and locate functions we need.
1. `LoadLibraryA` : loads DLLs
2. `GetModuleHandleA` : gets the base address of a loaded DLL
3. `GetProcAddress` : resolves symbols

But... the base address of kernell32.dll is not initially known in an exploit environment, so we will need to locate it, resolve function addresses from it, and do the same for any other required DLLs.

# Finding kernel32.dll
kernel32.dll is nearly guaranteed to be loaded into any given process since its APIs are required form my processes to run. There are multiple ways to retrieve to kernel32 base address, like with SEH and "Top Stack", but the most portable (and only one which works on recent Windows versions) is the PEB Method.

### PEB Method
> The linked lists mentioned below are implemented as substructures contained within each `_LDR_DATA_TABLE_ENTRY`, which are unique records for every module loaded into a PEB. The values in `_PEB_LDR_DATA` are the "start" nodes for each linked list.

A PEB structure is given for every running process and is pointed to by any of its given TEBs
1. Attach WinDbg to process
2. Dump the TEB to get the PEB location: `dt nt!_TEB @$teb` -> read 0x030
3. Dump the PEB to get the module "LDR" address: `dt nt!_PEB XXXXXXXX`x
4. Dump the LDR data : `dt _PEB_LDR_DATA XXXXXXXX`
	1. Where LDR is a pointer to a struct containing a start nodes to 3 linked lists (InLoad | InMemory | InInit Order) of loaded modules 
5. Dump the `_LIST_ENTRY` of inInitialization : `dt _LIST_ENTRY xxxxxxxx`
6. Dump the LDR Table metadata of the first entry given in the InInit List: `dt _LDR_DATA_TABLE_ENTRY (0xXXXXXXXX - 0x10)`
	1. The `_LIST_ENTRY` is a linked list substructure contained within `_LDR_DATA_TABLE_ENTRY`
	2. this struct isn't found from walking through the PEB/TEB struct, needs to be known beforehand (given by course material). If walking the InInitializationOrderLinks, then it resides 0x10 before the `_LIST_ENTRY` address (on x32 systems, and 0x20 before on x64 systems)

### Assembling the Shellcode
Use Keystone Engine and CTypes library in Python to build a script that will:
- Turn assembly into opcodes
- Allocate memory for the shellcode
- Copy the shellcode to allocated memory
- Execute the shellcode
[[Keystone Engine]]
```
import ctypes, struct
from keystone import *

CODE = (
	"start:					"	#
	"	int3				;"	# breakpoint for debugging, remove before deployment!
	"	mov ebp, esp		;"	# move ebp up to esp addr, simulating a func call and perserving params
	"	sub esp, 60h		;"	# move esp up another 0x60 to avoid clobbering the stack
	
	"find_kernel32:	"			#
	"	xor ecx, ecx		;"	# 
	"	mov esi,fs:[ecx+30h];"	#
)

### generate shellcode ###
ks = KS(KS_ARCH_x86, KS_MODE_32) # init keystone engine for x32
encoding, count = ks.asm(CODE) # where .asm compiles the instruction in CODE
print("Encoded %d instructions..." % count)
sh = b""
for e in encoding:
    sh += struct.pack("B", e) # for each item, add the given byte object from an unsigned char (B)
shellcode = bytearray(sh)

### test the the generated shellcode within the script ###
# Allocates a memory page with PAGE_EXECUTE_READWRITE protections and makes a pointer
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))
# copy the shellcode to a c_char buffer space
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
# copy the buffer into the memory page
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))
# pause execution so the user can attach windbg to python.exe									 
print("Shellcode located at address %s" % hex(ptr))
input("...ENTER TO EXECUTE SHELLCODE...")
# runs the shellcode in a new thread of python.exe
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.c_int(-1))									 

```
see https://docs.python.org/3/library/struct.html#format-characters for info on struct.pack

https://bsodtutorials.wordpress.com/2021/06/14/windows-address-translation-deep-dive-part-1/

article about segmentation and wtf the fs/gs segment registers are pointing to.



# Thoughts on note structure?
- Reference
-- Links
-- Succinct Application / Usage
--- Explanation

- Walkthrough
-- Objective
-- Links?
-- Definitions
-- Context -> Execution -> Repeat

- Thoughts