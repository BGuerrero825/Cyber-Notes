nmap -> HTTP File Server
metasploit version -> exploit for reverse shell
*searching for flag* couldnt find user "bill" desktop... I'm dumb and need to scroll up on ls output
PowerUp (GitHub powershell enum exploit) -> AdvancedSystemCareService9 (weak file perm)
msfvenom -> create reverse TCP shell payload
upload payload and inject into Service9's exec path, restart Service9
- write access but no delete access to process directory, got stumped for a bit trying to figure out Write-ServiceProcess (or whatever name was)