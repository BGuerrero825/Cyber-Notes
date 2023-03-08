The process:
Enumerate targets -> Discover live hosts -> Reverse-DNS lookup ->
Scan ports -> Detect versions -> Detect OS ->
Traceroute -> Scripts -> Write Output

Subnetworks:
125.65.127.0/24 (has ~250 hosts) vs 125.64.0.0/16 (has ~65k hosts)

Nmap ranges
127.78.122.13/29 -> starts scan at ...8 (last 3 bits zero'd)
127.75.0-255.121.135 -> performs 256 x 15 scans

ARP -> IP to MAC resolutions within a routed network, Data Link Layer protocol
ICMP -> Internet Control Management Protocol, Network Layer (no ports!)

Host Discovery with ICMP:
nmap will do ping by default, then attempt port scans on responding hosts
Often networks will block ping by default, -PP for a ICMP timestamp scan or -PM for mask queries which both also provide replies.

arp-scan --localnet OR arp-scan -l
-I (capital i): ex. -I eth0 to specify interface 0 

Host Discovery with TCP and UDP:
With TCP, nmap sends the SYN, open ports will SYN/ACK, and closed ones with RST.
Port for TCP can be specified with -PSXX ex. -PS21, or -PS21-30, or PS80,443,8080. Use -PA for Ack scan with similar functionality
UDP packets expect a ICMP port unreachable packet on failed delivery
Masscan is also an option for aggressive/quick sweeping scans. ex. masscan MACHINE_IP/24 -p22-25 OR --top-ports 100

nmap does reverse-DNS by default, use -n to skip this, or -R to try even for offline hosts. 