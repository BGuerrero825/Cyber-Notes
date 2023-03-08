SSL and TLS Certificate logs -> https://crt.sh

Google: `-site:www.tryhackme.com  site:*.tryhackme.com`

dnsrecon
sublist3r
gobuster

Virtual Hosts: Hosts not posted publically through DNS like test/dev versions or admin protals. 
`/etc/hosts` or `c:\windows/system32\drivers\etc\hosts`

`ffuf -w /usr/share/wordlists/SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.acmeitsupport.thm" -u http://MACHINE_IP -fs {size}`
where -fs is the file size of the returned page (filtering for real pages with results)