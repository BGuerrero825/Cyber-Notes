-sN: Null scan | closed ports should reply RST
-sF: FIN scan
-sX: Xmas scan (FIN, PSH, URG)
-sM: Maimon scan
-sA: ACK scan | port always responds RST, no response means firewall
-sW: Window scan
--scanflags URGACKPSHRSTSYNFIN: custom flag scan
-S Fake_IP: search with spoofed IP
--spoof-mac Fake_MAC: search with spoofed MAC
-D Decoy_IP,Decoy_IP,RND,ME: send traffic from decoy, random, and my IP
-sI Zombie_IP: Uses idle device and IP IDs to indirectly scan a machine
-f, -ff: fragment IP data into 8 bytes or 16 bytes | splits the TCP header across multiple IP packets to bypass IDS'
--source-port PORT: specify source port
-data-length NUM: append data to reach given length
--reason: how Nmap made a conclusion
-v, -vv: verbose
-d, -dd: debugging

Spoof ex. nmap -e INTERFACE -Pn -S SPOOF_IP TARGET
must specify -Pn so nmap will not expect a ping reply, since the reply traffic is routed to a spoofed IP

Idle Scan:
Its very important that the "zombie/idle" device is idle because an idle scan relies on incrementing IP ID's to gauge response from the target. Attacker SYN/ACK's zombie to get a starting value for IP ID, then sends a SYN to the target from the zombie IP. 3 potential outcomes: if open, the target will send the zombie a SYN/ACK which prompts the zombie to send a RST and thus incrementing zombie's IP ID. When we SYN/ACK the zombie again, we will see that the IP ID has incremented more than once, signifying that it responded to the target's SYN/ACK and that the port was open. If closed or filtered, the zombie will receive a RST or nothing from the target and when we SYN/ACK the zombie again it should only have an IP ID incremented by one.