central database for the OS, contains system configuration information and user information. 

Key : basic unit of data in the Registry, can nest subkeys while also containing a value.
Value : Name | Data Type | Data Content
Predefined Key: a key that stays open so it can be invoked by a program to request other keys for editing
Hives: a set of keys / values associated to specific files that get loaded into memory upon system boot, authentication, etc.

HKEY_CLASSES_ROOT (HKCR) : 
files types and properties. Subkeys are used by shell applications and [[COM]] apps

HKEY_CURRENT_CONFIG (HKCC) :
hardware configs for the OS which supersede default configs

HKEY_CURRENT_USER (HKCU) : 
current users configurations, varies with user logon session

HEY_LOCAL_MACHINE (HKLM?) :
local machine I/O, memory and drivers
HKLM\\SAM, HKLM\\Security, HKLM\\Software, HKLM\\System

HKEY_PERFORMANCE_DATA : 
system performance, not stored in the Registry but referenced by Reg functions

HKEY_USERS : 
default settings assigned to new users, HKEY_USERS\\.DEFAULT

Run / RunOnce : keys allowing programs to run upon user authentication. Program is a Value of the Key. RunOnce programs are deleted from the key after running
ex's.
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce

[[reg]] or run `regedit`

User password hashes are stored in the SAM and SYSTEM keys, which can be exported with `reg export`

### Data Types

![[Pasted image 20230429160109.png]]