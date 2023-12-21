```
"""
Pykd Gadget Discovery Tool
"""

from pykd import *
import sys, time

HEADER =  "#"*80 + "\r\n"
HEADER += "# findrop.py - pykd module for Gadget Discovery\r\n"
HEADER += "#"*80 + "\r\n\r\n"

##MEM_ACCESS = {
##0x1   : "PAGE_NOACCESS"                                                    ,
##0x2   : "PAGE_READONLY"                                                    ,
##0x4   : "PAGE_READWRITE"                                                   ,
##0x8   : "PAGE_WRITECOPY"                                                   ,
##0x10  : "PAGE_EXECUTE"                                                     ,
##0x20  : "PAGE_EXECUTE_READ"                                                ,
##0x40  : "PAGE_EXECUTE_READWRITE"                                           ,
##0x80  : "PAGE_EXECUTE_WRITECOPY"                                           ,
##0x101 : "PAGE_NOACCESS PAGE_GUARD"                                         ,
##0x102 : "PAGE_READONLY PAGE_GUARD "                                        ,
##0x104 : "PAGE_READWRITE PAGE_GUARD"                                        ,
##0x108 : "PAGE_WRITECOPY PAGE_GUARD"                                        ,
##0x110 : "PAGE_EXECUTE PAGE_GUARD"                                          ,
##0x120 : "PAGE_EXECUTE_READ PAGE_GUARD"                                     ,
##0x140 : "PAGE_EXECUTE_READWRITE PAGE_GUARD"                                ,
##0x180 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD"                                ,
##0x301 : "PAGE_NOACCESS PAGE_GUARD PAGE_NOCACHE"                            ,
##0x302 : "PAGE_READONLY PAGE_GUARD PAGE_NOCACHE"                            ,
##0x304 : "PAGE_READWRITE PAGE_GUARD PAGE_NOCACHE"                           ,
##0x308 : "PAGE_WRITECOPY PAGE_GUARD PAGE_NOCACHE"                           ,
##0x310 : "PAGE_EXECUTE PAGE_GUARD PAGE_NOCACHE"                             ,
##0x320 : "PAGE_EXECUTE_READ PAGE_GUARD PAGE_NOCACHE"                        ,
##0x340 : "PAGE_EXECUTE_READWRITE PAGE_GUARD PAGE_NOCACHE"                   ,
##0x380 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD PAGE_NOCACHE"                   ,
##0x701 : "PAGE_NOACCESS PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"          ,
##0x702 : "PAGE_READONLY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"          ,
##0x704 : "PAGE_READWRITE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"         ,
##0x708 : "PAGE_WRITECOPY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"         ,
##0x710 : "PAGE_EXECUTE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"           ,
##0x720 : "PAGE_EXECUTE_READ PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE"      ,
##0x740 : "PAGE_EXECUTE_READWRITE PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE" ,
##0x780 : "PAGE_EXECUTE_WRITECOPY PAGE_GUARD PAGE_NOCACHE PAGE_WRITECOMBINE" ,
##}

MEM_ACCESS_EXE = {
0x10  : "PAGE_EXECUTE"                                                     ,
0x20  : "PAGE_EXECUTE_READ"                                                ,
0x40  : "PAGE_EXECUTE_READWRITE"                                           ,
0x80  : "PAGE_EXECUTE_WRITECOPY"                                           ,
}

PAGE_SIZE = 0x1000
MAX_GADGET_SIZE = 8


BAD = ["clts", "hlt", "lmsw", "ltr", "lgdt", "lidt" ,"lldt", "mov cr", "mov dr",
    "mov tr", "in ", "ins", "invlpg", "invd", "out", "outs", "cli", "sti"
    "popf", "pushf", "int", "iret", "iretd", "swapgs", "wbinvd", "call",
    "jmp", "leave", "ja", "jb", "jc", "je", "jr", "jg", "jl", "jn", "jo",
    "jp", "js", "jz", "lock", "enter", "wait", "???"]

def log(msg):
 """
 Log a message to console.
 @param msg: Message string
 @return: None
 """
 print("[+] " + msg)

def getModule(modname):
 """
 Return a module object.
 @param modname: string module name
 @return: pykd module object
 """
 return module(modname)

def isPageExec(address):
 """
 Return True if a mem page is marked as executable
 @param address: address in hex format 0x41414141.
 @return: Bool
 """
 try:
     protect = getVaProtect(address)
 except:
     protect = 0x1
 if protect in MEM_ACCESS_EXE.keys():
     return True
 else:
     return False

def findExecPages(mod):
 """
 Find Executable Memory Pages for a module.
 @param mod: module object returned by getModule
 @return: a python list of executable memory pages
 """
 pages = []
 pn = int((mod.end() - mod.begin()) / PAGE_SIZE)
 log("Total Memory Pages: %d" % pn)
 for i in range(0, pn):
     page = mod.begin() + i*PAGE_SIZE
     if isPageExec(page):
         pages.append(page)
 log("Executable Memory Pages: %d" % len(pages))
 return pages

def findRetn(pages):
 """
 Find all return instructions for the given memory pages.
 @param pages: list of memory pages
 @return: list of memory addresses
 """
 retn = []
 for page in pages:
     ptr = page
     while ptr < (page + PAGE_SIZE):
         b = loadSignBytes(ptr, 1)[0] & 0xff
         if b not in [0xc3, 0xc2]:
             ptr += 1
             continue
         else:
             retn.append(ptr)
             ptr += 1
             
 log("Found %d ret instructions" % len(retn))
 return retn
 
def formatInstr(instr, mod):
 """
 Replace address with modbase+offset.
 @param instr: instruction string from disasm.instruction()
 @param mod: module object from getModule
 @return: formatted instruction string: modbase+offset instruction
 """
 address = int(instr[0:8], 0x10)
 offset = address - mod.begin()
 return "%s+0x%x\t%s" % (mod.name(), offset, instr[9:])

def disasmGadget(addr, mod, fp):
 """
 Find gadgets. Start from a ret instruction and crawl back from 1 to
 MAX_GADGET_SIZE bytes. At each iteration disassemble instructions and
 make sure the result gadget has no invalid instruction and is still
 ending with a ret.
 @param addr: address of a ret instruction
 @param mod: module object from getModule
 @param fp: file object to log found gadgets
 @return: number of gadgets found starting from a specific address
 """
 count = 0
 for i in range(1, MAX_GADGET_SIZE):
     gadget = []
     ptr = addr - i
     dasm = disasm(ptr)
     gadget_size = dasm.length()
     while gadget_size <= MAX_GADGET_SIZE:
         instr = dasm.instruction()
         if any(bad in instr for bad in BAD):
             break
         gadget.append(instr)
         if instr.find("ret") != -1:
             break
         dasm.disasm()
         gadget_size += dasm.length()
     matching = [i for i in gadget if "ret" in i]
     if matching:
         count += 1
         fp.write("-"*86 + "\r\n")
         for instr in gadget:
            try:
                fp.write(str(instr) + "\r\n")
            except UnicodeEncodeError:
                print(str(repr(instr)))
 return count
     
if __name__ == '__main__':
 print("#"*63)
 print("# findrop.py pykd Gadget Discovery module #")
 print("#"*63)
 
 count = 0
 try:
     modname = sys.argv[1].strip()
 except IndexError:
     log("Syntax: findrop.py modulename [MAX_GADGET_SIZE]")
     log("Example: findrop.py ntdll 8")
     sys.exit()

 try:
     MAX_GADGET_SIZE = int(sys.argv[2])
 except IndexError:
     pass
 except ValueError:
     log("Syntax: findrop.py modulename [MAX_GADGET_SIZE]")
     log("Example: findrop.py ntdll 8")
     log("MAX_GADGET_SIZE needs to be an integer")
     sys,exit()
     
 mod = getModule(modname)
 if mod:
     pages = findExecPages(mod)
     retn  = findRetn(pages)
     if retn:
         fp = open("C:/tools/pykd/findrop_output.txt", "w")
         fp.write(HEADER)
         start = time.time()
         log("Gadget discovery started...")
         for ret in retn:
             count += disasmGadget(ret, mod, fp)                        
         fp.close()
         end = time.time()
         log("Gadget discovery ended (%d secs)." % int(end-start))
         log("Found %d gadgets in %s." % (count, mod.name()))
     else:
         log("ret instructions not found!")
 ```