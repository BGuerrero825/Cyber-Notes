Used to perform complex **"Static Analysis"** of a program, whereas a debugger is **"Dynamic Analysis"**
Install link: https://www.hex-rays.com/products/ida/support/download_freeware/
```
chmod +x idafree70_linux.run
sudo ./idafree70_linux.run
sudo ln -s /opt/idafree-7.0/ida64 /usr/bin
ida64
```

Get notepad.exe to the linux system running IDA, then open it in IDA

"Portable executable for 80386 \[pe64.so\]" is the common processor type for 32-bit Windows exe's and DLL's

### Graph View | Text View | Proximity View
Green and Red arrows indicate branch paths for true and false conditions respectively.
Blue arrows are non-conditional jumps.
proximity view is a more advanced feature for viewing and browsing the relationships between functions, global variables, and constants
- View > Open Subview > Proximity Browser
- Options > General > Line prefixes - to get virtual addresses in Graph view
- Blocks can be color-coded
- (;) - add comment to assembly line
- (N) - name currently opened function
- Alt-M - create bookmark
- Ctrl-M - go to bookmark

### Search Functionality
- Alt-I - search immediate value, like a hardcoded DWORDs
- Alt-B : search byte sequences
- Ctrl-P : open function jump window
- Ctrl-F : filter functions
- Ctrl-L : jump by name (global variables)
On global var or function, (X) : to check cross-references (xrefs) in the program

# Static-Dynamic Analysis
We can use IDA as control flow guide for WinDbg analysis. 
- Attach WinDbg to the process, `lm m notepad` to get the base address
- IDA -> Edit -> Segments -> Rebase Program
- ex. sync
	- WinDbg : `u notepad!GotoDlgProc`
	- IDA : `g` -> type in start address from WinDbg

### Tracing Notepad
Tracing the code flow of notepad.exe opening a text file
- Get notepad to call CreateFileW
	- create a text file on Windows
	- `bp kernel32!CreateFileW` : this is the API function used to get a file's handle for read and write access -> `g`
	- Try to open the file with notepad, triggering the breakpoint 
	- (IDA) Imports, find CreateFileW, xref on it to find calls to it in the code, but there are 20 options
- Find where notepad calls CreateFileW
	- `pt` : to continue until the return of CreateFileW, `p` : to follow the return back
	- Use the landing address to find the matching code in IDA with `g` (assuming it is rebased to the WinDbg session)
- Get file text from ReadFile call
	- (IDA) find consequent call to ReadFile API, we see a preceding argument lpBuffer which receives the data from the read file
	- `bp READFILE_AADR` -> `g` : continue to ReadFile call
	- `dds esp L5` : find the address pushed to the stack as lpBuffer (pushed first, so 2nd one down)
	- `p` : to step over ReadFile call -> `da LPBUFFER_ADDR` : to get file contents