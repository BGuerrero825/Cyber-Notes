OpenSSL

- `apt list openssh-server` : check if its installed, should be on Kali
- `mkdir /etc/ssh/default_keys` -> `mv /etc/ssh/ssh_host_* /etc/ssh/default_keys/` : to move default keys out of the config path (security reasons)
- `dpkg-reconfigure openssh-server` : to regenerate keys
- `vi /etc/ssh/sshd_config` : optional, edit config file
[[systemctl]]
- `systemctl enable ssh.service`
- `systemctl start ssh.service`
- `systemctl stop ssh.service`
- `systemctl disable ssh.service`
- optionally make a new user account `useradd -> usermod`
- [[scp]]