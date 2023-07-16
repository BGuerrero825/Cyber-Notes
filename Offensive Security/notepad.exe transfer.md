*This is a tangent of how I tried to get notepad.exe off of the lab machine and into my local Kali instance for analysis*

- universal.ovpn to VM via open OpenSSL's ssh server on the VM (see [[SSH Server]]) and using ssh on my local Windows (which works out of the box), ez. 
- After establishing that I could SSH to my VM, just scp from remote to server [[scp]]

- Fun trying to move notepad.exe from shitty Windows VM (RDP'd into over VPN connection on the VM)
	1. figure out what tools I have to make outbound connections on the Windows VM. No nc, ssh, ftp. But I have python!
	2. Open nc listener on Linux and send to out file, `nc -lp 8000 > out.txt`
	3. Prep file for transfer on Windows with Powershell `certutil -encode IN_FILE OUT_FILE`
		1. But we get some START and END CERTIFICATE stuff, and new lines every X amount of chars. Whatever, just transfer that for now.
	4. Launch python.exe and use sockets to connect to the listener
	```
	#this may not be verbatim... just a reference
	import socket
	s = socket.socket()
	s.connect('IP', 8000)
	f = file.open(r'NOTEPAD.EXE_PATH','rb')
	l = f.read(1024)
	while (l):
		s.send(l)
		l = f.read(1024)
	s.close()
	```
	5. Back on Linux, `vi out.txt`, delete top and bottom cert lines. Then replace all new line chars with nothing [[vi]]
	6. Decode it with `base64 -d out.txt > notepad.exe`
	7. yay :)