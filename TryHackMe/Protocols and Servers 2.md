These protocols are vuln to attacks, namely: Sniffing (network packet capture), Man-in-the-Middle Attack, Password Attack (authentication).
Evil CIA Triangle = DAD (Disclosure, Alteration, Destruction)

Sniffing Attack:
Tcpdump, Wireshark, Tshark - useful tools for inspecting traffic.
sudo tcpdump port 110 -A  // A: display in ASCII format
Wireshark has keyword filters, ie. POP, IMAP, HTTPS

MITM Attack:
HTTP, FTP, SMTP, POP3 all vulnerable. Messages that don't authenticate or integrity check with cryptography will be vulnerable. PKI, root certificates, and TLS protect from TLS.

SSL/TLS:
End-to-end encryption of cleartext protocols.
DNS over TLS -> DoT
HTTP 80 -> HTTPS 443
FTP 21 -> FTPS 990
Telnet 23 -> SSH (SCP and SFTP) 22
SMTP 25 -> SMTPS 465
POP3 110 -> POP3S 995
IMAP 143 -> IMAPS -> 993
Protocols will: establish TCP connection, establish SSL/TLS connection, then send protocol traffic.
SSL/TLS Handshake"
1) Client sends ClientHello, indicating support capes/algorithms
2) Server responds ServerHello, gives selected algorithm for connection, provides certificate if prompted, and sends information to generate the master key, end with ServerHelloDone
3) Client responds with ClientKeyExchange, containing additional info for master key, then switches to using encryption with ChangeCipherSpec message.
4) Server switches to encryption with its own ChangeCipherSpec message.

SSH:
Identity of remote server is confirmed, exchanged messages are encrypted, both sides can detect modification.
ssh username@SERVER_IP
scp = secure copy
scp username@SERVER.IP:/this/is/a/directory/file.tar.gz ~ //copy remote file to ~ on my pc
scp myfile.tar.bz2 username@SERVER_IP:/target/directory/  //copy my file to remote server
SFTP, FTP through SSH != FTPS on port 990
uname, uname -r : get os and kernel version

Password Attack:
Hydra, password attacker
hydra -l username -P wordlist.txt server service 
hydra -l mark -p /usr/share/wordlists/rockyou.txt 10.10.74.138 ftp
-l username: provide login name
-P wordlist.txt: specify password list
server service: provide server IP and service to attach
-s PORT: use to specify non-default ports
-V, -vV: verbosity, shows username and password combos tried
-d: debugging output
-t: threads, connections to target
