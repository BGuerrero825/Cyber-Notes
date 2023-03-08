nmap 
-F: reduces scan from 1000 to 100 most used ports
-sT: for full connect scan
-sS: for Syn Scan (default w/ privileges)
-sU: for UDP scan
-p-: all ports
-T<0-5>: scan aggressiveness
--max-rate 50: 50 packets/sec
--min-parallelism 100: 100 probes run in parallel