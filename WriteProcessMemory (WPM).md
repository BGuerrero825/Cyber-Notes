This assignment prompts that WriteProcessMemory must be used to achieve DEP bypass
```
BOOL WriteProcessMemory(
	HANDLE hProcess,
	LPVOID lpBaseAddress,
	LPCVOID lpBuffer,
	SIZE_T nSize,
	SIZE_T *lpNumberOfBytesWritten
)
```
- hProcess: handle to the desired process, in this case -1 will get the current process. The intent is to perform a copy operations in the current process
- lpBaseAddress: absolute memory address in the code section where the new code will be written. The exploit should avoid overwriting existing code.
	- Compiled code is page-aligned. When the opcodes don't use up the whole page the rest of the page will be nulled (0x00's). This can be used to find where the "code cave" (space for the new injected code) begins
- lpBuffer: source buffer where the new code will be copied from
- nSize: the number of bytes to write in
- See MSDN for more info: https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory

### WPM's Address
1. First, in order to use WriteProcessMemory, I need to know where that function exists in the context of the current process
2. From the paused WinDbg session attached to osed.exe I can start interrogating the process PE header to find segment information
	1. run `.load narly`, `!nmod` or just `lm` in WinDbg to see the modules currently loaded
3. `!dh -a osed` : will list information about the headers and segments of the osed module
	1. Under "OPTIONAL HEADER VALUES" are the address and sizes of various directories
4. I are specifically curious about the "Import Address Table Directory" (IAT) as this will give us the address of a pointer to WPM from the osed module 
	1. The output says its at address (offset) 0x3000 and has a size of 0x14c
5. `dps osed+3000 osed+3000+14c` to show the contents of the symbols in this table table
6. I see: `63103020  74882890 KERNEL32!WriteProcessMemoryStub`
	1. `63103020` is the IAT memory address, and `74882890` is the pointer to WPM contained within it