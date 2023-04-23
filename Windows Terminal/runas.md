### Usage
a Windows binary to inject new credentials into memory of the current machine. Useful when we have new credentials and already have a foothold on a machine but the network doesn't allow for new network connections / machines to be added.


### Useful Examples
- `runas.exe /netonly /user:DOMAIN\USERNAME cmd.exe`


### Options
- /netonly - load credentials, but don't authenticate to domain controller. Network connections will occur using the specified account, but local commands will not
