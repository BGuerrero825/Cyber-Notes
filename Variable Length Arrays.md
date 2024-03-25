Stack Frames:
func1 calls func2, we are in the middle of func2 execution
```
| ////// ESP: Top of func2 stack
| 
| other local vars
| var3 (array[x])
...
| var3 (array[0])
...
| var4 (float)
| var3 (pointer to VLA)
| var2 (array[3])
| var2 (array[2])
| var2 (array[1])
| var2 (array[0])
| var1 (int)
| ////// EBP: Bottom of func2 stack, varue is previous EBP
| Return Address to func1 code
| param1 to func2
| param2 to func2
| param3 (pointer) to func2
| 
...
| param3 value (pass by reference)
```

The first task of an entered function is to set up its local variables with their proper values, `var1` and `var2` for example. The locations of these locally scoped variables must be consistent relative to EBP at compile time (since their references are hard baked into the compiled instructions) and therefore can't change based on the runtime variables. As seen with `var2` an array sized at compile time will push the locations of following variables upward. VLAs would make the location of following variables inconsistent. However, the stack space after the variable initializations is less picky and can be dynamically sized.

This problem is solved by initializing the VLA as a pointer to an array that will exist further up the stack frame. Then, additional logic is compiled into the function entry to dynamically size the stack at the runtime to create space after the local variables where the values of the VLA will live. The reliably sized pointer is then set to the address of wherever this array now exists in the stack frame.