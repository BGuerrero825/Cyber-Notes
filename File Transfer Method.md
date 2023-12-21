Transfer files from another machine on a network with python (on Windows) and nc (on Linux)
1. On Windows Powershell: `[Convert]::ToBase64String([IO.File]::ReadAllBytes("path\to\file")) > file.txt` on desired file
2. Linux: `nc -lvnp 8000 > file.txt`
3. Windows Python(3):
```
import socket
s = socket.socket()
s.connect(('IP', 8000))
f = open(r'base64\file.txt','rb') # use file.open if version < python3
l = f.read(1024)
while (l):
	s.send(l)
	l = f.read(1024)
s.close()
```
4. Linux: `base64 -di file.txt > file.dll`