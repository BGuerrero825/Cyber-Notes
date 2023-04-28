[[listdlls]]

DLL's are formatted line .exe's, it's easy to add and extend .dll's. Can be called at the same time by multiple programs.
(in 64 bit Windows):
- System32 : 64 bit libraries (32 on 32 bit Windows)
- SysWOW64 : 32 bit libraries

HAL.DLL :
	Hardware Abstraction Layer, kernel mode library, unable to be used by User mode programs
NTDLL.DLL : 
	New Technology DLL, allows User mode programs to call the Windows Native API (when other APIs haven't loaded yet) during startup, etc.
KERNEL32.DLL : 
	allows programs to use Win32 base APIs like memory management, I/O operations, etc., uses NTDLL.DLL for much of its functionality
USER32.DLL : 
	allows programs to call objects in the UI like desktop, taskbar, and Start menu.
ADVAPI32.DLL : 
	allows programs to call security features and registry manipulation
