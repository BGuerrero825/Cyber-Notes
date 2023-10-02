PE structures:
`_IMAGE_DOS_HEADER` : address of the base of any PE
`e_lfanew` : Decimal value offset to PE File Header

Portable Executable (PE): file format with headers that informs the dynamic linker how the file data should be mapped into memory.

Image file: Executable file / memory image, any .exe or .dll file.

Object file: A file given as input to the linker, from which it produces the image file, which is input to the loader.

File pointer: location of an item in the file prior to being processed by a linker or loader. Differs from a Relative Virtual Address

Section: code or data portion that must be loaded contiguously.

PE file = MS-DOS MZ header + stub program + PE file signature + PE file header + the PE optional header + all of the section headers + all of the section bodies.

Structures:
https://doxygen.reactos.org/d5/db1/dll_2win32_2dbghelp_2compat_8h_source.html#l00145
https://www.aldeid.com/wiki/PE-Portable-executable

More aid:
https://tech-zealots.com/malware-analysis/pe-portable-executable-structure-malware-analysis-part-2/
https://upload.wikimedia.org/wikipedia/commons/1/1b/Portable_Executable_32_bit_Structure_in_SVG_fixed.svg