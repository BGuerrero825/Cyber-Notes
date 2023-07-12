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
Green and Red arrows indicate branches that were or were not taken.
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