# Host Survey
1. Initial Access Vetting
	- Is the target safe to operate on? Vetted via: system config, running processes and their owners, logged on users and their privileges, scheduled tasks, suspicious activity, malware running or installed, security products, and logging.
2. Malware/Security Product/Process prosecution
	- Closer examination of suspicious processes and software identified in step 1. Getting an idea of what is normal for a given OS / version and quickly identifying anomalies or threats.
3. Exit Vetting
	- More checks of determine if any changes have occurred between first accessing the box and clean-up. Check for: new users and privileges, new connection, new processes, and file changes (made by me or that capture my activity).


# Cutsheet
A text document for copy and paste commands that will be run frequently to perform reliable vetting on a new machine. Record any useful commands as they are encountered and constantly refine / organize the cutsheet with every op.

# Opnotes
Don’t copy and paste every command ran. Focus on output that gives important info that is relevant to future operations like OS info, anomalous configurations, or suspicious activity. Use the `script` command to log the terminal and keep the opnotes succinct and high level.

# Op Plan
Scheme of Maneuver notation: ‘> BOX_NAME’ mean access to specified box,  ‘-‘ indicates traffic to the following target must be routed through a previous step, a hop (can have multiple hops)
Ex. 
```
> Operations Box
-> Target 1
--> Target 2
--> Target 3
---> Target 4
```

> started building cutsheet and running through a given ops plan


# OP NOTES

- Initial access on Target 1: 18:28:05 UTC
- System in EDT
- no root cronjobs
- Doggo has a 30 min cronjob to log changes to /var/log
- 2 interfaces
- user John, uid 1008
- running Ubuntu 20.04.3 LTS
- kernel 5.4.0-107-generic
- initialized with systemd
- Ruby service to foreign host with SYN_SENT, listener on :631 started by cupsd
- cupsd has a log file /var/log/cups/access_log open for read and write
- there is one ip neighbor at 192.168.0.1 (_gateway)
- an alert alias is setup to do a notify-send to desktop (this is generally standard on some distros?)
- ssh daemon root login is: prohibit-password
- rsyslog logs to the remote host 192.168.0.1:514 for all events (*.*)

### Process Trustworthiness
A process name can't be trusted just by itself, also check process ancestry, binary path, user, and CLI options. Example: a root /bin/bash shell running from a unpriv user and spawned from an Apache service


# New stuff
script
date -u 
date +%s : print date in Unix epoch format
id
hostnamectl
stat /sbin/init : get verbose file "status"
netstat -paunt : program names and PID, "all" listening and non-listening, udp, no name resolution, tcp
ps -Half : Hierarchical listing, all processes, long format, full output
lsof : list open files. FD = file Descriptor as: txt, mem, cwd (current dir), rtd (root dir) OR (FD# + r|w|u) u = r&w. SIZE/OFF = size of the file or its offset in bytes 
ip XXX
w -i : lists all logged in users and their IP
bash login scripts : /etc/profile, ~/.bash_profile and alternatives
getent : get entry
/home/USER/.bash_history
rsyslog : rocket system logging service, check /etc/rsyslog.conf for any remote logging
find ... -perm ... : mode = all in ugo must be exactly the mode, -mode = all in ugo must have at least 1 overlapping bit set with mode,  /mode = one in ugo must have at least 1 overlapping bit with mode
- SSH -L option, bind_address is the local interface to be accepting connections (localhost by default)



IPC : Inter-process communication == Unix Domain Sockets

 





