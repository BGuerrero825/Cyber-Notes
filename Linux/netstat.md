shows existing communications

`netstat`

`netstat -tunlp` : check all listening connections

`-a` 
"all" show all listening ports and established connections
`-t`/`-u` 
show only TCP or UDP protocols
`-l` 
show ports in listening mode
`-s` 
list network statistics by protocol
`-p`
list connections with service name and PID info
`-i`
show interface statistics, (good info about network usage)
`-ano` 
(a) show all sockets, (n) don't resolve DNS, (o) display timers
