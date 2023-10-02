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
6. Dump the LDR Table data of the first entry given in the InInit List: `dt _LDR_DATA_TABLE_ENTRY (0xXXXXXXXX - 0x10)`
	1. The `_LIST_ENTRY` is a linked list substructure contained within `_LDR_DATA_TABLE_ENTRY`
	2. this struct isn't given from walking through the PEB/TEB struct in WinDbg, needs to be known beforehand (given by course material). If walking the InInitializationOrderLinks, then it resides 0x10 before the `_LIST_ENTRY` address (on x32 systems, and 0x20 before on x64 systems)
 7.  Walk the Flinks until we find the BaseImage of `KERNEL32.DLL`

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


### assembly code ###
CODE = (
        "start:                  " #
        "   int3                ;" # DEBUGGING PURPOSES: Interrupt exec to attach debugger
        "   mov ebp, esp        ;" # move up the base pointer to imitate a function call
        "   sub esp, 60h        ;" # move up the stack pointer to avoid stack clobbering

        "find_kernel32:          " #
        "   xor ecx, ecx        ;" # zero out ecx
        "   mov esi,fs:[ecx+30h];" # get the PEB address (30h into the TEB)
        "   mov esi,[esi+0Ch]   ;" # get the Ldr address from PEB
        "   mov esi,[esi+1Ch]   ;" # get the InItOrder first link address from Ldr
        
        "next_module:            " #
        "   mov ebx, [esi+8h]   ;" # get the module base address of the linked entry 
        "   mov edi, [esi+20h]  ;" # get the module name
        "   mov esi, [esi]      ;" # get the flink entry
        "   cmp [edi+12*2], cx  ;" # check for null byte at word 13 (byte 26) of module name (KERNEL32.DLL)
        "   jne next_module     ;" # move on to next module if no match
        "   ret                  " #
        )


### generate shellcode ###
# init engine in x86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)
sh = b""
for e in encoding:
    sh += struct.pack("B", e) # add each byte object from an unsigned char (B)
shellcode = bytearray(sh)


### makes the shellcode executable ###
# allocate mem page with PAGE_EXEC_READWRITE perms, returns a pointer
ptr = ctypes.windll.kernel32.VirtualAlloc(ctypes.c_int(0),
                                          ctypes.c_int(len(shellcode)),
                                          ctypes.c_int(0x3000),
                                          ctypes.c_int(0x40))
# tbh not sure here, but makes a ctype compatible buffer space from the shellcode
buf = (ctypes.c_char * len(shellcode)).from_buffer(shellcode)
# move the buffer into the memory page
ctypes.windll.kernel32.RtlMoveMemory(ctypes.c_int(ptr),
                                     buf,
                                     ctypes.c_int(len(shellcode)))


### executes the shellcode ###
print("Shellcode located at address %s" % hex(ptr))
input("...PRESS ENTER TO EXECUTE SHELLCODE...")
# creates the thread environment for the shellcode to run
ht = ctypes.windll.kernel32.CreateThread(ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.c_int(ptr),
                                         ctypes.c_int(0),
                                         ctypes.c_int(0),
                                         ctypes.pointer(ctypes.c_int(0)))

ctypes.windll.kernel32.WaitForSingleObject(ctypes.c_int(ht), ctypes.int(-1))
```
see https://docs.python.org/3/library/struct.html#format-characters for info on struct.pack

https://bsodtutorials.wordpress.com/2021/06/14/windows-address-translation-deep-dive-part-1/ : article about segmentation and wtf the fs/gs segment registers are pointing to.

1. copy this to Windows machine, save as python file
2. run it from cmd : `python SCRIPT.py`
3.  Continue execution
4. set breakpoint at compare
5. `g` until we find a `du eip` that matches `KERNEL32.DLL`, step through to make sure the code catches this case
	1. Note that WinDbg will resolve the full path name under BaseDllName, but only the module name (`KERNEL32.DLL`) is actually in memory
6. .... finish this another time

# Resolving Symbols
At this point we can find `kernel32.dll` but we will crash the program due to not properly ending the process. We need to resolve APIs exported by the module like `TerminateProcess` and before that, `GetProcAddress`. Rather than relying on the API, we can create our own "GetProcAddress" equivalent by traversing the Export Address Table (EAT) of a loaded DLL

### Export Directory Table Method
A method to resolve symbols from kernel32.dll and other DLLs
> symbols : function names and their starting memory addresses.

All DLL's that export functions have an Export Directory Table that contains:
- Number of exported symbols
- Relative Virtual Address (RVA) of the export-functions array
- RVA of the export-names array
- RVA of the export-ordinals array
EDT Structure
```
typedef struct _IMAGE_EXPORT_DIRECTORY {
  DWORD Characteristics;
  DWORD TimeDateStamp;
  WORD MajorVersion;
  WORD MinorVersion;
  DWORD Name;
  DWORD Base;
  DWORD NumberOfFunctions;
  DWORD NumberOfNames;
  DWORD AddressOfFunctions;
  DWORD AddressOfNames;
  DWORD AddressOfNameOrdinals;
}
```

To find the address of a specific function:
1. Resolve symbol by name, looking for it in `AddressOfNames` array and noting its index "i"
2. Use this "i" to index into `AddressOfNameOrdinals` array and noting its value as "j"
3. Use this "j" to index into `AddressOfFunction` array, getting a function RVA
4. Add the Relative Virtual Address to the Base (DLL) Address to get a true Virtual Memory Address: RVA + BA = VMA (Virtual Memory Address)

In this example, we optimize the shellcode by using a hashing function that turns the string name we're searching for into a four byte hash allowing us to reuse the assembly for any given symbol name.

Then, once the `LoadLibraryA` symbol is resolved we can load in these arbitrary modules


### Working with the Export Names Array
EDT contains relative addresses, but we can get the VMA using the DLL base address stored in EBX from the `find_kernel32:` section of our shellcode.

shellcode.py updates:
```
import ctypes, struct
from keystone import *

CODE = (
    " start:                             "  #
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!
    "   mov   ebp, esp                  ;"  #
    "   sub   esp, 0x200                ;"  #   More space to avoid stack clobber
    "   call  find_kernel32             ;"  #
    "   call  find_function             ;"  #

    " find_kernel32:                     "  #
    "   xor   ecx, ecx                  ;"  #   ECX = 0
...
...
    " find_function:                     "  #
    "   pushad                          ;"  #   Save all registers
                                            #   Base address of kernel32 is in EBX from 
                                            #   Previous step (find_kernel32)
    "   mov   eax, [ebx+0x3c]           ;"  #   Offset to PE Signature
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Table Directory RVA
    "   add   edi, ebx                  ;"  #   Export Table Directory VMA
    "   mov   ecx, [edi+0x18]           ;"  #   NumberOfNames
    "   mov   eax, [edi+0x20]           ;"  #   AddressOfNames RVA
    "   add   eax, ebx                  ;"  #   AddressOfNames VMA
    "   mov   [ebp-4], eax              ;"  #   Save AddressOfNames VMA for later

    " find_function_loop:                "  #
    "   jecxz find_function_finished    ;"  #   Jump to the end if ECX is 0
    "   dec   ecx                       ;"  #   Decrement our names counter
    "   mov   eax, [ebp-4]              ;"  #   Restore AddressOfNames VMA
    "   mov   esi, [eax+ecx*4]          ;"  #   Get the RVA of the symbol name
    "   add   esi, ebx                  ;"  #   Set ESI to the VMA of the current symbol name
    
    " find_function_finished:            "  #
    "   popad                           ;"  #   Restore registers
    "   ret                             ;"  #
...
```

[[Portable Executable (PE)]] - see doxygen link for struct docs
`find_function:`
- VMA/RVA : Virtual Memory Address/Relative Virtual Address, in this case, of the export-arrays function and the AddressOfNames list
> ebx now stores kernel32 base, thanks to `find_kernel32:`
1. pushad stores stack values
2. `move eax,[ebx+0x3c]` : get PE header address stored at 0x3c offset from module base (in the PE DOS header)
3. `mov edi,[ebx+eax+0x78]` : get the RVA of the export-functions array from offset 0x78 in the PE header (base addr + PE header RVA + offset)
4. `add edi,ebx` : add the previous RVA to the base address to get the VMA of export-functions
5. `mov ecx,[edi+0x18]` : get NumberOfNames (num of exported symbols, will be used as a counter to parse AddressOfNames) from offset 0x18 in VMA
6. `mov eax,[edi+0x20]` : get RVA of AddressOfNames array from offset in export-functions
7. `add eax,ebx` : add the AddressOfNames RVA to the base address to get VMA of AddressOfNames
8. `mov [ebp-4],eax` : save AddressOfNames on the stack