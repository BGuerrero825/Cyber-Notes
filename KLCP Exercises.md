## About Kali Linux
- Live Boot: OS boots to RAM
	- Forensics mode: doesn't auto-mount any drives, `noautomount` boot param
- Install: OS boots to a storage device
- `mount` to see mounted devices (verify forensics boot)
- Kali Rolling is base on Debian Testing
- Kali Features: A live system, forensics mode, a custom Linux kernel, completely customizable, a trusted operating system with default disabled network services, ARM support, preloaded security tools

## Getting Started
Live boot stuff
- `wget` to kali website
- `gpg` : GNU Privacy Guard, implementation of OpenPGP, provides digital encryption and signing
- `dd if=inputfile of=/dev/outfile bs=1M` : convert and copy file

## Linux Fundamentals
- `file`, `/dev/snd/seq` the sound device is a "character special", and `/dev/sda1` the hard disk partition is a "block special"
	- Character device is one which driver communicates by sending single characters (bytes, octets)
	- Block device is one which driver communicates by sending blocks of data
- [[Background jobs]]
- `dmesg` : prints messages from kernel message buffer, often from device drivers
- `find` vs `locate` : locate uses a precompiled db, unique to some linux distros
- `time COMMAND` : to test command runtime
- `dmesg | grep CPU0`, `lspci | grep Ethernet` : hardware info (device/kernel msg buffers)
- `free -h`, `df -h` : available memory
- `lsusb`

## Installing Kali
- Reqs: 2GB RAM and 20 GB disk space
- LUKS and Logical Volume Management (LVM) for disk encryption
- ARM install: `dmesg` to get disk ID, and `dd if=... of=/dev/DMESG_OUTPUT, bs=1M`
- `chroot`

## Configuring Kali Linux
- `adduser`, `passwd`, `usermod -a -G`, `chsh -s`
- Network Manager, `nmcli dev status`
	- `systemctl stop|disable|start|enable`, `service` is a wrapper for it
	- `/lib/systemd/system/`
- `ifconfig eth0 down` : bring down an interface
- `ifup wlan0`, `ifdown ...` `ifquery`
- `tee` : read from stdin and write to stdout or file
- [[iptables]]

## Getting help
- `man [1-9] COMMAND`
- `info` docs use `pinfo`
- `apt show package PACKAGE`
-  Look for: `/usr/share/doc/package/`
- https://www.kali.org/docs/
-  irc.oftc.net 
- determine source of a file: `dpkg -S /PATH/TO/FILE` or command: `dpkg -s ...`

## Securing Kali Linux
- `fail2ban`
- `iptables` or `fwbuilder` (graphical)
- `top`
- `logcheck`
- `dpkg -V`
- Advanced Intrusion Detection Environment (AIDE)