Web Browser:
FoxyProxy - lets you quickly change the proxy server you are using to access the target website. Good for feeding to Burp.
User-Agent Switcher and Manager gives you the ability to pretend to be accessing the webpage from a different operating system or different web browser.
Wappalyzer - provides insights about the technologies used on the visited websites.

ping -c **#_PINGS** **IP**
ping = ICMP echo/type 8, ping reply = ICMP echo reply/type 0
It works at the IP layer (layer 3), has no concept of ports

traceroute **IP**
(Win) tracert
Uses an incrementing TTL to map a route to a target. Tries 3 packets and records the IPs of those that return an ICMP error (due to ping request reaching end of TTL). Some servers are configured to not return this error.

telnet for HTTP banner grabbing
telnet **HOST** **PORT** -> GET / HTTP/1.1 -> host: whatever

netcat connecting on HTTP
nc  **HOST** **PORT** -> GET / HTTP/1.1 -> host: whocares