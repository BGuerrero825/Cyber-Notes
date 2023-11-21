1. Enable shared folders from the VM settings & and set a path (and name) on the host system
2. `vmware-hgfsclient` : on VM to get available shares from the host
3.  `sudo mkdir -p /mnt/hgfs/share` : creating directory mount point on VM (dont do this if this dir already exists, it may be created by default?)
4. `sudo vmhgfs-fuse .host:/share /mnt/hgfs/share -o allow_other -o uid=1000` : to fuse the host share directory to the VM share folder, allowing all users to access and setting default user as file owner (kali)
- Where host is `.host:/SHARE_NAME_SET_IN_VMWARE`
5. `ln -s /mnt/hgfs/share /home/kali/Desktop/share` : creates a symbolic link to the desktop
