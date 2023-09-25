ntoskrnl.exe : NT Operating System Kernel ("kernel image"), performs hardware abstraction, process handing, and memory management. Contains cache manager, security reference monitor, scheduler (Dispatcher), the blue screen of death.
Check WDK and functions preprended by Ke for low level documentation for drivers and such.

.NET Framework : consists of 2 components
- Common Language Runtime (CLR) : run-time engine for .NET. Includes a JIT compiler for Common Intermediate Language (CIL). garbage collection, type verification, code access security, etc.
- The .NET Framework Class Library (FCL) : collection of types implementing functionality needed for client and server apps like UI, networking, DB, etc.

Process vs Program :
- Program is a static sequence of instructions
- Process has virtual address space, open handles to resources, a security context (access token), pid, threads, and is typically started by a .exe program.

Csrss.exe (environment subsystem process) loaded for each session and loads : Basesrv.dll, Winsrv.dll, Sxssrv.dll, and Csrsrv.dll


