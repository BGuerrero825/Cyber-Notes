Discover files, videos, pictres, backups, pages, and features on a website. 

Manual, Automated, or OSINT (Open Source Intel)

Manual:
http:/HOST/robots.txt - restricts search engine crawls
favicon - use webste icon md5sum to discover framework used to build website, check against OWASP database
http://HOST/sitemap.xml - shows what search engines should show
http header - curl http://HOST -v or telnet HOST -p 80/443
Framework Stack

OSINT:
Google Hacking / Dorking : `site:EXAMPLE.com, inurl:admin, filetype:pdf, intitle:admin`
Wappalayzer - search technologies/APIs/version numbers on a website
`https://archive.org/web/` - Wayback Machine
GitHub
S3 Bucket - Amazon AWS (simple) storage service for files / web content, `http(s)://HOST.s3.amazon.aws.com`

Automated:
CLI tools for dir spamming
ffuf - `ffuf -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt -u http://MACHINE_IP/FUZZ`
dirb - `dirb http://MACHINE_IP/ /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt`
Gobuster - `gobuster dir --url http://MACHINE_IP/ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/common.txt`