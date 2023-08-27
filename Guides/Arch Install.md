Beginner's Guide: https://wiki.archlinux.org/title/User:Alad/Beginners%27_guide
Guide: https://wiki.archlinux.org/title/Installation_guide
Good Article for Install + KDE Plasma: https://medium.com/@adithya.anilkumar1/installing-arch-linux-with-kde-plasma-or-gnome-desktop-dual-booting-with-windows-ad7e1f090894
Download ISO from mirror on https://archlinux.org/download/ 
### UEFI vs BIOS boot
if `/sys/firmware/efi/efivars` exists, then there's a UEFI mobo and the system booted with systemd-boot for UEFI systems
### Keyboard, Fonts, Time
`loadkeys us` is the default, its autoloaded
`setfont ...` where fonts are listed in `/usr/share/kbd/consolefonts/`
`showconsolefont`
`timedatectl set-ntp true` (network time sync) or `timedatectl set-timezone US/Central`	

### Partitions
`lsblk`
`cfdisk` - boot (> 1 MB), swap (~allocated RAM size), filesystem (the rest)

### Swap setup
`mkswap /dev/sdaX`
`swapon /dev/sdaX`

### Filesystem mount
`mkfs.ext4 /dev/sdaX`
`mount /dev/sdaX /mnt`
If EFI boot, it needs to also be mounted `mkdir /mnt/boot` , `mount /dev/sdaX /mnt/boot`
check with `df`
### Firmware 
`pacstrap /mnt base linux linux-firmware`
`genfstab -U /mnt  >> /mnt/etc/fstab` (fstab = filesystem table)

### Locales
`arch-chroot /mnt`, hop into root on the installed system
`hwclock --systohc` (sync to hardware clock)
`pacman -Sy vim` [[pacman]]
`vim /etc/locale.gen` -> uncomment `en_US.UTF-8`
`locale-gen`
`vim /etc/locale.conf` -> type `LANG=en_US.UTF-8`
`vim /etc/hostname` -> whatever name
### Users 
`passwd`, set root user password to something secure :)
`useradd -g users -m babu` -> `passwd babu`
### Boot Manager (BIOS)
`pacman -S grub`
`grub-install --target=i386-pc /dev/sda` (disk, not partition name)
`grub-mkconfig -o /boot/grub/grub.cfg`

### Network Drivers
`pacman -S networkmanager network-manager-applet dialog wireless_tools wpa_supplicant mtools dosfstools base-devel  linux-headers`
	`systemctl start <OR enable> NetworkManager`

### Reboot
`exit` (from `arch-chroot /mnt` root user)
`unmount -a`
`reboot`

### Sudoers settings
`EDITOR=nano visudo` - config to your liking


### Graphics drivers and server
`pacman -S xf86-video-amdgpu`
`pacman -S xorg`
`pacman -S xorg-server`

### KDE Plasma
`pacman -S sddm`, display manager
`systemctl enable sddm`
`pacman -S plasma <OPTIONALLY kde-applications>` (big install)
`reboot`
`sudo pacman -Syyu`
:)

#### Terminals
- Alacritty
- cool-retro-term