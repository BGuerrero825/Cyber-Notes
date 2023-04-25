### Usage
removes specified sections from each file line
`cat /etc/password | cut -d ":" -f 1` (only shows users from field 1 of users file)


### Useful Examples
- 

### Options
- `-b NUMBER`: select these bytes only (position in line)
- `-c NUMBER`: select these characters only (position in line)
- `-d DELIMITER`: use specified char as delimiter (`-f` required)
- `-f NUMBER`: select these fields (specified by delimiter)