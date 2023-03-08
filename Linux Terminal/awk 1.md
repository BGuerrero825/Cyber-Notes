### Usage



### Useful Examples
- `sudo tcpdump -n -r traffic.pcap | awk -F  " " '{print $3}' | sort | uniq -c | head`
	- print field 3 of packet capture, sort by occurrence, counting duplicates, only showing the top 10


### Options
- 