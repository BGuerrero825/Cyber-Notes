Beginner's Guide: https://wiki.archlinux.org/title/User:Alad/Beginners%27_guide
Guide: https://wiki.archlinux.org/title/Installation_guide

VM Install*
1. Download ISO from mirror on https://archlinux.org/download/ 
2. Prepare install medium (VM in this case)
3. Boot up
4. (Optional) set keyboard layout and font
5. Verify boot mode `cat /sys/firmware/efi/fw_platform_size` : 64 or 32 = 64 or 32 bit UEFI boot, file doesn't exist = BIOS boot. This depends on your mobo.
6. Connect to the internet `ip link` and test with `ping ...`
7. Set time `timedatectl ...`
8. Partition the disk (based on step 5 boot method), `fdisk -l` or `lsblk` to list disk devices, then `cfdisk` and make a boot (BIOS boot 256M), swap (Linux swap ~4G), and filesystem partition (Linux filesystem, rest of system)
9. Format the partitions, `mkfs.ext4 /dev/sda3` for linux filesystem, `mkswap /dev/sda2` and `swapon -a` for swap partition (GRUB doesn't need BIOS boot to be formatted)
10. Mount partitions `mount /dev/sda3 /mnt` for filesystem and ``

Desktop Environment


#### Terminals
- Alacritty
- cool-retro-term