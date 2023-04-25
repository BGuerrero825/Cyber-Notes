*unique commands from bash, no output redirection. Flow: sytem shell -> msfconsole prompt -> context prompt -> meterpreter prompt -> target system shell*

# msfconsole
`COMMAND -h`
`search` -> `use` -> `show options`
`set RHOSTS` `file:FILEPATH`, or network range with CIDR (10.10.151.0/24) or range (10.0.0.10 - 10.0.0.35)
`back`, `info`
`check` *supported by some modules, will check if target is vulnerable before running*
`exploit / run` `-z`  (or -j) to auto background the session
`background` or CTRL-Z
`sessions' -SESSION_NUM`

# Search
`search -S "*login" -t exploit smb rank:gte300` , search smb exploits, filter for keyword 'login' and with rank "normal" or above
#### Port scanning
`search portscan`
#### UDP service identification
`scanner/discovery/udp_sweep`
#### SMB Scans (Server Message Block - Network file sharing protocol)
`scanner/smb/smb_version`, `scanner/smb/smb_enumshares`

# Single vs. Staged
Stages: Downloaded by the stager after access is achieved on the target
`generic/shell_reverse_tcp` - denotes an single payload
`windows/x64/shell/reverse_tcp` - denotes a staged payload (stager + stage)

# Exploit 
`show options` -> `set PARAMTERS`
`show payloads` for more specific use cases
`sessions -i SESSION -c COMMAND`, run a command on a session without switching to it