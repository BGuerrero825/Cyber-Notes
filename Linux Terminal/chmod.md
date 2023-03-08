change file permissions

`chmod u,g,o FILE/DIR`
`chmod -R 777 ~/example_dir`
(change all modifiable files in dir to rwx permission)
`chmod ug+rw example.txt
(give read and write to owner and group)
`chmod 4744 example.txt`
(set the SUID of file, prepend with 2 for SGID, and 1 for sticky)

permissions: (u)owner, (g)group, (o)others
`-R`: recursive, use on directories

