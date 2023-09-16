## LINUX SURVEY

script

ssh ...

timedatectl // date && date -u

ls /etc/cron*

cat /etc/crontab // cat /var/spool/cron/crontabs/XXX // crontab -l

ifconfig // ip addr

id

uname -a // hostnamectl

uname -r

lsb_release -d

stat /sbin/init

sudo netstat -paunt

ps -Half

sudo lsof

ip neigh // arp -n

?? echo $SHELL

w -i

groups USER

which EXE_FILE

alias

less /home/USER/.bash_history

less /etc/ssh/sshd_config

less /etc/rsyslog.conf // less /etc/rsyslog.d/XXX

find / -mmin -30 2>/dev/null


## WINDOWS SURVEY

date /t

time /t

ipconfig

systeminfo

ver

hostname

whoami /all
whoami /priv

net user NAME

net localgroup GROUP

query user

tasklist /v
tasklist /svc

netstat -bona


## SSH TUNNEL

ssh -L BINDED_LOCAL_INTERFACE_IP:LOCAL_LISTEN_PORT:REMOTE_FORWARD_TO_IP:REMOTE_FORWARD_TO_PORT USER@REMOTE_IP
ssh -L 0.0.0.0:22:3389.168.0.1:3389 john@192.168.0.213/