# -----CUTSHEET-----
>RECORD
- script
## LINUX SURVEY

>TIME
- timedatectl
	- date && date -u

>OS
>KERNEL
- uname -a
- hostnamectl
- lsb_release -d
	- cat /etc/os-release
	- cat /etc/redhat-release
- less /etc/issue

>BOOT
- ps -p 1
- stat /sbin/init

>CRONJOBS
- ls /etc/cron*
- cat /etc/crontab
- cat /var/spool/cron/crontabs/XXX
- sudo crontab -u USER -l

>IP 
>NETWORK
- ifconfig
	- ip addr
- ip neigh
	- arp -n

>PROCESSES
>CONNECTIONS
- sudo netstat -paunt
- ps -Half
- sudo lsof
- systemctl list-unit-files --state=enabled

>USERS
>SHELL
- w -i
	- users
- groups USER
- echo $SHELL
- which EXE
- alias
- less /home/USER/.bash_history
- printenv

>LOGGING
- less /etc/ssh/sshd_config
- less /etc/rsyslog.conf 
  less /etc/rsyslog.d/XXX

>MODIFICATION
- find / -mmin -30 2>/dev/null

>MODULES
- [/sbin/]lsmod
- less /proc/modules

>IPTABLES
- sudo [/usr]/sbin/iptables -t TABLE -L -v -n





## WINDOWS SURVEY

>TIME
- date /t && time /t

>OS
>KERNEL
- systeminfo
- ver

>CRONJOBS

>IP 
>NETWORK
- ipconfig
- hostname
- - net view \\COMPUTERNAME

>PROCESSES
>CONNECTIONS
- tasklist /v
- tasklist /svc
- netstat -bona
- schtasks /query
	- \Windows\System32\Tasks
- wmic process get *
- wmic where (parentprocessid=320 and handlecount=70) get handlecount,name,processid,parentprocessid

>USERS
>SHELL
- whoami /all
- whoami /priv
- net user NAME
- net localgroup GROUP
- query user

>LOGGING
- auditpol /get /category:*

>SERVICES
- sc query
- sc queryex
- sc qc 
- wmic service get /?

>REGISTRY
- reg query HKLM /s /f RunOnce
- reg query HKLM /s /f 1rc-server.exe /t REG_SZ

>MODIFICATION
- dir /TC /OD
- Get-ChildItem | Sort CreationTime | Select-Object Name,CreationTime

>SHARES
- net share NEWSHARE=C:\Users
- net use z: \\172.16.0.70\Tools /user:Administrator L33tHax0r
- net use z: \delete

>NETSH
- netsh interface portproxy show all
- netsh advfirewall firewall show rule name=all





## SSH

>LOCAL LISTEN
- Listen on local network, pass through SSH session, forward on remote network
- ssh -L LOCAL_LISTEN_IP:PORT:REMOTE_FORWARD_IP:PORT USER@REMOTE_IP
	- ssh -L 0.0.0.0:22:3389.168.0.1:3389 John@192.168.0.213

>REMOTE LISTEN
- Listen on remote network, pass through SSH session, forward to local network (requires root on remote)
- ssh -R REMOTE_LISTEN_IP:PORT:LOCAL_FORWARD_IP:PORT USER@REMOTE_IP
- ssh -R 0.0.0.0:445:172.16.0.70:445 John@IP

- ~C for command line ssh while in session
- 
>REMOVE TUNNEL
- -O cancel -L||-R PREV_COMMAND
- -KL||-KR BIND_ADDR:PORT

>SCP
- scp John@IP:"/path/to/the/file\ you\ want" /home
