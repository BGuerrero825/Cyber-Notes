### Usage
 programming language designed for text processing, typically used as a data extraction and reporting tool


### Useful Examples
- `awk -F : '($2 != "x") {print}' /etc/passwd`
	- print off any passwords stored in the passwd file
- `sudo tcpdump -n -r traffic.pcap | awk -F  " " '{print $3}' | sort | uniq -c | head`
	- print field 3 of packet capture, sort by occurrence, counting duplicates, only showing the top 10

### Options
- `-F` : Field separator
- `'{printf}'` : print without newlines