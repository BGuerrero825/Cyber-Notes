### Usage
Impersonate another user.
	Windows binary to inject new credentials into memory of the current machine. Useful when we have new credentials and already have a foothold on a machine but the network doesn't allow for new network connections / machines to be added.


### Useful Examples
- `runas.exe /netonly /user:DOMAIN\USERNAME cmd.exe`
- `runas /noprofile /user:administrator cmd`
- `runas /profile /env /user:mydomain\admin "mmc %windir%\system32\dsa.msc"`
- `runas /env /user:user@domain.microsoft.com "notepad \"my file.txt\""` : use user creds to open file, but from the context of the remote user


### Options
- `/netonly` : "remote access only", doesn't authenticate to domain controller. Network connections will occur using the account, but local commands will not.
- `/env` : use the current environment instead of the local user's environment (this can be used to `runas` from an otherwise inaccessible dir)