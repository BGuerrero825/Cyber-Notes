show all users on the system, and might have some password hashes

`cat /etc/password`
`cat /etc/password | cut -d ":" -f 1` , more print friendly
`cat /etc/password | grep home`, shows real users

Format 
https://www.cyberciti.biz/faq/understanding-etcpasswd-file-format/
`username : password : userID : groupID : userID info (comment) : home dir : command/shell`