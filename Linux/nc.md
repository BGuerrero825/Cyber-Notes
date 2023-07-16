*creates a connection to an IP on a specific port, or listens on a specific port*

`nc IP -p PORT` : make a connection
`nc -lvnp PORT` : local listener (a CLASSIC)

`nc -z -v HOST_IP 22-3389(PORT_RANGE)` : scuffed port scanner

`nc -l -p 8000 > out.file` : receive a file and write out
`nc -w 3 IP 8000 < in.file` : send a file over TCP

-l: listener
-v: verbose output
-n: numeric-only IPs, no DNS
-p: specify port #

