### Prompt
Given iMC suite, find an exploit in the TFTP server on a UDP port.

### Enumeration
1. Run TCPView, look for the TFTP server
	1. Its called tftpserver.exe
2. Look what ports it accepts input on
	1. 69 (default TFTP) and others
3. Quick python script to send big input to these ports
	1.  Since its UDP, use `s.sendto(INPUT, (IP, PORT))`, no `s.connect` and ensure socket declared as `socket.SOCK_DGRAM`