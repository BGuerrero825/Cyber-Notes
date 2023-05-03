### Program Memory
![[Pasted image 20230430093531.png]]

- Program threads will execute from the Program Image and from referenced DLLs. 
- Each thread has its own stack.
- x86 has dedicated PUSH and POP instructions 

Calling Conventions : how functions receive parameters and how they return results. Usually determined by the compiled but sometimes specifiable by the programmer
	Params can be placed in CPU registers or pushed on a stack, etc. Order of the parameters varies. How stack is prepared and cleaned with a call. What CPU registers must be preserved for the caller

Stack Frame : section of stack data dedicated to a single function call. Begins with a return address and parameters

[[CPU Registers]]

Debugger : a proxy between the program instructions and CPU execution
Memory Spaces : Kernel-mode (ring 0) and User-mode (ring 3)
