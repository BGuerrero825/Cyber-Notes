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
5. Dump the `_LIST_ENTRY` of inInit
6. Dump the LDR Table metadata of the first entry given in the InInit List: `dt _LDR_DATA_TABLE_ENTRY (0xXXXXXXXX - 0x10)`
	1. The `_LIST_ENTRY` given from step 4 is just a structure with a forward and back link address, but is part of a larger structure which beings 0x10 before that address (if using the InInit address)