Sometimes are internet facing, instead of being isolated to the network
Examples:
- Mail Exchange exposing an Outlook Web App (OWA) login
- Remote Desktop Protocol
- VPN endpoints integrated with AD
- Web applications
Note: Brute Forcing would probably lock us out since AD enforces locks after failed login attempts
### Password Spraying
Instead, using OSINT, we find a default password that was supposed to be changed and a list of account names in the org. Password spraying will try a single password against many accounts. 
Use a python script [[ntlm_passwordspray]] and a username list
`python ntlm_passwordspray.py -u usernames.txt -f za.tryhackme.com -p Changeme123 -a`