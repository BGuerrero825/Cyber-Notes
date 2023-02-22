Connect to HTTP via Telnet: 
telnet TARGET_IP 80
GET /index.html HTTP/1.1
host: telnet
HTTP Server choices: Apache, Internet Information Services (IIS), nginx

FTP: Initiates on 21 (Control), transfers on 20 (Data)
STAT - additional information
SYST - System Type of target
PASV - Passive (data sent on a separate channel, from FTP client's port above port 1023), Active (data sent on a separate channel, from FTP server port 20)
TYPE A - file transfer mode to ASCII
TYPE I - file transfer mode to binary
get FILENAME

Mail Submission Agent (MSA) - Processes mail submission for transfer
Mail Transfer Agent (MTA) - Sends mail to delivery agent
Mail Delivery Agent (MDA) - Recipient mailbox
Mail User Agent (MUA) - End to end mail client
[MUA] --SMTP--> [MSA/MTA] --SMTP--> [MTA/MDA] --POP3/IMAP--> [MUA]
POP3: 
USER namehere -> PASS passhere
STAT -returns-> +OK nn mm, **nn = number of email in inbox, mm = size of inbox in bytes
LIST -> RETR 1, returns first message
IMAP:
Allows for sync across devices through an IMAP server
c1 LOGIN username pass -> c2 LIST "" "*" -> c3 EXAMINE INBOX -> c4 LOGOUT  **IMAP requires a string (anything) before each command

FTP: File Transfer (21)
Telnet: Remote Access (23)
SMTP: Email, MTA (25)
HTTP: Web (80)
POP3: Email, MDA (110)
IMAP: Email, MDA (143)
**MDA, Mail Delivery Agent // MTA, Mail Transport Agent**

DNS Zone Transfers on TCP 53, Domain Name Resoultion on UDP 53
