## Windows
-Find input fields to the program
Use a script to recreate packet and spam variable input
-Fuzz (give long strings to) any inputs to create a crash/error, locating a vulnerable input
-Overflow to EIP (instruction pointer), verifiable using a debugger on the program process
-Find space for shellcode ie. overflow into as much memory space as possible
-Find a jump instruction to a register in the overflow space eg. JMP ESP, point EIP to that instruction address (must be in a static location)
-Overflow shellcode into the pointed to space. 

NOP Sleds

Limited ESP space? Use jump code to access in ESP space to get to another overflowable register space

