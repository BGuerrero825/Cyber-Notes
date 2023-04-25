> Since Linux systems have a single directory tree, if we were to insert a USB drive (for example), we would need to create an associated location somewhere in that tree. Creating that associated location is called _mounting_.

display current mounts or mount new ones

`mount -t FORMAT` : show all mounts of FORMAT type

### USB Mount Example
- `sudo fdisk -l` : get info about connected drives
- `sudo mkdir /mnt/usb`
- `sudo mount /dev/sdb1 /mnt/usb` : mount from original dir (as seen in `fdisk` to mount location)
- `cd /mnt/usb` -- `ls -la`
### Unmount
- `cd ~` : get out of the dir first
- `sudo umount /mnt/usb`

[[fdisk]]