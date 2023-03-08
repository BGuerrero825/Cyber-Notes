msfconsole - the CLI
Modules - exploits, scanners, payloads, etc..
Tools - standalone tools like msfvenom, pattern_create, and pattern_offset.

Auxiliary: Scanners, fuzzers, crawlers, supporting modules, etc.
Encoding: tries to obfuscate exploit methods and payloads so that signature based security anti-virus don't detect them. Limited success against anti-virus' that perform additional checks.
Evasion: Will actively try to avoid antivirus
Exploits: attack, listed by target system
Payloads: Exploits will use a vulnerability but payloads give the desired result ie. shell, running a program, backdoor, etc.
- Singles: self contained payload (add user, launch app), does not download additional components to run
- Stagers: Sets up the connection between Metasploit and the target system. The stager will be uploaded to the target ahead of any stages so that the upload file size is smaller, less intrusive.
- Stages: Downloaded by the stager after access is achieved on the target
`generic/shell_reverse_tcp` - denotes an single payload
`windows/x64/shell/reverse_tcp` - denotes a staged payload (stager + stage)
Post: used after vulnerability exploitation for additional info/access

msfconsole
Can be used like a normal command line, but not output redirection
`help COMMAND`
`set RHOSTS` file:FILEPATH, or network range with CIDR (10.10.151.0/24) or range (10.0.0.10 - 10.0.0.35)
`set RPORT, LPORT, LHOST, SESSION, PAYLOAD', session used for post-exploitation, payload used for staged payloads
`unset OPTION` or "all"
`setg` set global
`use EXPLOIT_PATH` (or number from search)
`show options`
`show MODULE_TYPE'
`back`
`info`
`search KEYWORD` type:PAYLOAD
`exploit / run` -z will automatically background the session
'check' *supported by some modules, will check if target is vulnerable before running
`background` or CTRL-Z
`sessions' -SESSION_NUM

"GreatRanking" is reliable and will typically autodetect appropriate target
"GoodRanking" works on common case, but not much autodetection
"NormalRanking" generally reliable given a specific version, no reliable autodetect

regular command prompt -> msfconsole prompt -> context prompt -> meterpreter prompt -> target system shell
