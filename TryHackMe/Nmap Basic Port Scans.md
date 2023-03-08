Responses:
Open: Reachable and serving
Closed: Reachable but non-serving
Filtered: Port is inaccesible, probably due to a firewall blocking request or response
Unfiltered: Reachable, but unsure if servering, found with ACK scan
Open|Filtered:
Closed|Filtered:

TCP Flags:
URG - skip previously sent TCP segments, process this immediately
ACK - acknowledges receipt of a segment based on ack number
PSH - Pass the data to the application promptly
RST - reset, or tear down, the current connection
SYN - using a synchronization number to establish a connection
FIN - no more data to send
