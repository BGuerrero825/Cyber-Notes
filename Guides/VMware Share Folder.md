1. Enable shared folders from the VM settings & and set a path on the host system
2. `vmware-hgfsclient` : on VM to get available shares from the host
3.  `sudo mkdir -p /mnt/hgfs/share` : creating directory mount point on VM
4. `sudo vmhgfs-fuse .host:/share /mnt/hgfs/share -o allow_other -o uid=1000` : to fuse the host share directory to the VM share folder, allowing all users to access and setting default user as file owner (kali)
5. `ln -s /mnt/hgfs/share /home/kali/Desktop/share` : creates a symbolic link to the desktop
