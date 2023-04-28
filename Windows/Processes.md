The **thread** is the thing happening, the **process** is the environment in which it happens, and the **program** is the procedure that the **thread** executes.

Kernel mode : direct access to hardware
User mode : typical, access to OS utilities only

`System` : PID 4, Kernel-mode program responsible for operating system mechanisms. Spawns:
	- `smss.exe` : Session Manager, maps virtual address space. It spawns twice, first time to spawn `winlogon.exe` and `csrss.exe` then exits, second it stays to watch the user session, if either of those processes die it will signal the OS to shutdown or crash.
	- `winlogon.exe` : authenticates users and loads user profiles, listens for Ctrl+Alt+Del, parent of `userinit.exe` which starts initial shell and `explorer.exe` then exits
	- `csrss.exe` : Client Server Runtime Process, runs several background functions, begins the shutdown sequence if terminated, parent of process that spawns `cmd.exe`
	- `explorer.exe` : Windows Explorer, renders Windows GUI (Start Menu, Taskbar, System Tray), spawns more processes
	- `wininit.exe` : Windows Startup, triggers a set of User mode applications that maintain system functionality, spawns more processes

[[tasklist]]
[[taskkill]]
[[wmic]] process

[[SysInterals]]