nmap **IP**
nmap -p **port(-port)** **IP**

nmap -80-180 192.168.199.0-255
*X.X.X.0-255 == X.X.X.0/24*

Common:
-sS: TCP SYN scan (silent/quick, default)
-sV: find service version running on port
-sn: disable port scanning (host discovery)
-sC: run default scripts
-F: reduces scan from 1000 to 100 most used ports
-p-: all ports
-O: OS detection
-oG FILE: grepable output
-A: "All", equal to -sV -O -sC --traceroute

Finer Control:
--sV --version-light, --version-all: try most likely 2 probes, or all 9 probes
-n / -R: reverse-DNS off/on(for all hosts)
--traceroute
--script=SCRIPTS
-sT: for full connect scan
-sU: for UDP scan
--max-rate 50: 50 packets/sec
--min-parallelism 100: 100 probes run in parallel
-f, -ff: fragment IP packet into 8 bytes or 16 byte
-T<0-5>: scan aggressiveness
--source-port PORT: specify source port
-data-length NUM: append data to reach given length

Niche Scans:
-PR: ARP scan (only on local network)
-PE: ICMP echo request (ping) scan
-PP: ICMP timestamp request scan
-PM: ICMP mask request scan
-PSxx: Syn scan with specified port
-PAxx: Ack scan with specified port
-PU: UDP scan
-sN: Null scan | closed ports should reply RST
-sF: FIN scan
-sX: Xmas scan (FIN, PSH, URG)
-sM: Maimon scan
-sA: ACK scan | port always responds RST, no response means firewall
-sW: Window scan
--scanflags URGACKPSHRSTSYNFIN: custom flag scan

output:
-oN FILE: output to normal format
-oG FILE: output to grepable format
-oX FILE: output to XML format
-oA FILE: output to all formats
--reason: how Nmap made a conclusion
-v, -vv: verbose
-d, -dd: debugging

Spoof / Idle:
-S Fake_IP: search with spoofed IP
--spoof-mac Fake_MAC: search with spoofed MAC
-D Decoy_IP,Decoy_IP,RND,ME: send traffic from decoy, random, and my IP
-sI Zombie_IP: Uses idle device and IP IDs to indirectly scan a machine



*nmap has to be run privelidged for a lot of functionality, specifically when trying non-standard protocol techniques

Responses:
Open: Reachable and serving
Closed: Reachable but non-serving
Filtered: Port is inaccesible, probably due to a firewall blocking request or response
Unfiltered: Reachable, but unsure if servering, found with ACK scan
Open|Filtered:
Closed|Filtered: