Discovering Command Inject: look for references to OS directories or system calls. Look for crafted shell input that can be hijacked. 

Blind Command Injection: try ping and sleep, then test if application is unresponsive. Otherwise, try outputting a command to a file via '>' and cat the file.
Verbose Command Injection: Linux- whoami, ls, ping, sleep, nc (revsh). Windows- whoami, dir, ping, timeout.

PHP Vulnerable Functions: Exec, Passthru, System. Interact with OS to execute shell commands. Use regex to sanitize input (PHP ex. "[0-9]+", accepts only numeric) or predefined functions. Using hexadecimal values will often bypass the filter but be executed properly.