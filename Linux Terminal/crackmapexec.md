### Usage
A package of AD directed attacks, from enumerating logged on users and spidering SMB shares to executing psexec style attacks, auto-injecting Mimikatz/Shellcode/DLL’s into memory using Powershell, dumping the NTDS.dit and more.


### Useful Examples
- `crackmapexec -h`
- `crackmapexec PROTOCOL -h`
- `crackmapexec smb 10.10.10.172 -u users.txt -p users.txt` - iterate all users on smb and try username as password
- `crackmapexec smb 10.10.10.172 --pass-pol` - retrieves password policy from AD server

### Options
- 