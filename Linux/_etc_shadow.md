contains hashes of passwords for users

`*` in the password field means disabled account 

format:

https://www.cyberciti.biz/faq/understanding-etcshadow-file/

`username : password : last password change: minimum days (change pass) : maximum days : warn days : inactive (days before disable) : date of expiration`

Password field format:
`$id$salt$hashed`
where id is the algorithm used
- 1 = MD5
- 2a and 2y = Blowfish
- 5 = SHA-256
- 6 = SHA-512