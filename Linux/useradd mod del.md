add a user account
`sudo useradd -m babu` 
`-m` : create a home directory
`passwd babu` : prompt to set a password
`-s SHELL` : specify user shell on login

modify a user account

`sudo usermod -a -G GROUP_NAME USER_NAME` (add user to specified group)
`sudo usermod -s /usr/bin/zsh babu` change default shell