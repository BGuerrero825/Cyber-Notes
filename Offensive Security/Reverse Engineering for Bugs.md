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
Put WinDbg on the FastBackServer.exe process, then run a breakpoint on incoming connections with:
`bp wsock32!recv` 

Simple python script to send input to the socket:
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
  char   *buf,
  int    len,
  int    flags
);
```

1. `dds L5 esp` after hitting the breakpoint, we see the socket descriptor, then the char* address
2. the char* address space is populated once we finish the function, `pt`, then `da` that address to see the string
3.  eax will contain the byte length of the received string

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

Finding relevant code paths: 
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

Inspecting relevant code paths:
1. Set a breakpoint at `FastBackServer!FX_AGENT_CopyReceiveBuff+0xb4 - 5` (from previous section)
2. Once hit, dump the stack arguments being pushed with `dd esp L3`
	- This shows `04f54458 04f50058 00000004`, two buffer locations, and a length of 4. But we know our string is much larger...
3. Take note of the offset used in the destination buffer address, 4438h, from `lea eax, [edx+ecx+4438h]`, we'll look for this after this memcpy
4. Skip over the memcpy call since we know already know what that's going to do
5. The next time 4438h is used is in a function to swap endianess, this is often done by programs to parse input as entered (big endian) vs the little endian format its stored in. This then overwrites the +4438h that it was read from.
6. The next blocks of code perform various value checks on the buffer value. We want to stay in this right side execution stream because it contains another memcpy which might be vulnerable and ultimately ends with a push of 1 to eax and returns successfully.
	1. Our string of 'A's fails the `jbe` of 100000h check, so we need to reformat the first DWORD of our string (in the python script) and try again. `from struct import pack` and `buf = pack('>i', 0x1234)` to pack in big endian.
	2. Confirm it works by placing a breakpoint at the check instruction and verifying the jump instruction (and/or manually ensure the data being compared matches the check)
	3. Continue this process for any other failing checks.

Conditional Path Analysis:
1. Continue with dynamic analysis until we reach the `cmp` where the 0x1234 is being compared to 0x64 (decimal 100), which is the length of the rest of the buffer (after the first DWORD).  
	- The app can handle fragmented TCP packets, this function includes a check for fragmentation. dwHeaderLength of value 4 is added to our header, then the value 4 from edx+0x20 is subtracted right after, leaving the 0x1234 effectively unchanged for the comparison in this case.  
	- This signifies that the first DWORD is intended to match the input buffer size and act as a basic checksum for verifying the data.  
2. Update the python script with the first DWORD as 0x64 and breakpoint at this compare, `bc *` and `bp FastBackServer!FX_AGENT_CopyReceiveBuff+0x1f6`  `
3. Hitting the breakpoint and stepping, the code then passes the check, and in the following code block the DWORD is added, subbed, then moved to stack. It is then used as a size parameter for a memcpy, with the assumption being that the rest of the input buffer will be what is copied.  
4. We can `dd esp L3` and `dd SRC*_ADDR` to verify the parameters being pushed  
5. Stepping over the memcpy (note that the destination buffer is on the stack), the function then moves 1 into eax for a successful return. 
  
# Reverse Engineering the Protocol  
So far we identified the code that processes input to the server and found an initial checksum verification. Now, we continue onto the actual application functionality that will store and parse the malformed input, which is likely to reveal a vulnerability.

### Header-Data Separation

Tracking program flow to input parsing:
1. Follow the return from CopyReceiveBuff and see that it brings us to `FX_AGENT_GetData+0xd` 
2. Follow the flow with static-dynamic analysis.  
	- We then find a call to `FX_AGENT_CheckPacketIsComplete` which can be assumed to check if we have fully received the packet containing input. The previous section revealed that this is hardcoded to 0x440 bytes, so anything less than this (our packet) will pass.  
3. After this, `FX_AGENT_GetData` completes execution and bring us back to `FX_AGENT_Cyclic` (recall the call stack check `k` in WinDbg from earlier when we were in the recv call), presumably to begin parsing the input data.  
4. Again, follow the folow with static-dynamic analysis.  
	- We hit a call to `FXCLI_C_ReceiveCommand` which suggests our input is being used to form a command in the program.  
5. `dd esp L4` to see the arguments being pushed. There is value 1, our checksum of 0x64, a pointer to our 100 A's string, and a pointer set some bytes before that, presumably to the start of the packet received with metadata.  

-  In IDA we see a bunch of conditional blocks with offshoots to else conditions that all flow into error messages and lead to the same terminating block. We can imagine this as a series of nested if conditions in C.  
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

The checks in this example are:  
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
3. The next function of interest (that arguments we control are pushed to) after these copies is `FXCLI_OraBR_Exec_Command` which will likely use these buffers.  
  
From analyzing `FXCLI_C_ReceiveCommand` we deduce our buffer is structured in this way:  
```  
0x00 - 0x04: Checksum DWORD  
0x04 - 0x34: psAgentCommand  
0x34 - End:  psCommandBuffer
```  
  
### Reversing the Header