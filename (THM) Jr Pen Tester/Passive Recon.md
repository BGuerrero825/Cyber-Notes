whois - query public whois servers
nslookup, dig - query public dns servers
DNSDumpster, Shodan.io - online services that allow us to collect information about our target without directly connecting to it.

whois tryhackme.com
nslookup -type=**OPTION** **DOMAIN_NAME** **SERVER** Domain_name is the website to be searched, Server is the DNS server to ask from.
OPTIONS: -type=...
- A : IPv4 Addresses
- AAAA : IPv6 Addresses
- MX : Mail Servers
- CNAME : Canonical Name
- TXT : TXT Records
- SOA : Start of Authority
dig @**SERVER** **DOMAIN_NAME** **TYPE**

DNSDumpster - stores all DNS info on a domain (and subdomains) and displays in comprehensive format
Shodan.io - queries all internet connected devices and saves response info. Can search by domain, service, port, etc... and retrieve aggregate info