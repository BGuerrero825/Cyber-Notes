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