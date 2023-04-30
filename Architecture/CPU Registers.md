Modern CPU consists of nine 32-bit registers
![[Pasted image 20230430095235.png]]

### Important Registers
ESP - Stack pointer, most recently referenced point on the stack
EBP - Stack base pointer, stores the top of the stack at the moment when a function is called (stack frame pointer)
EIP - Instruction pointer, location of next instruction to execute in the program image. **Primary target in memory attack**

### General Purpose Registers
EAX (accumulator): Arithmetical and logical instructions
EBX (base): Base pointer for memory addresses
ECX (counter): Loop, shift, and rotation counter
EDX (data): I/O port addressing, multiplication, and division
ESI (source index): Pointer addressing of data and source in string copy operations
EDI (destination index): Pointer addressing of data and destination in string copy operations