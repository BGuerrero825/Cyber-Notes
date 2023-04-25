### Usage
Provided hashes, utilizes hash attacks to guess user passwords 
`hashcat [options]... hash|hashfile|hccapxfile [dictionary|mask|directory]`

### Useful Examples
-  `hashcat --force --stdout -r /usr/share/hashcat/rules/best64.rule password.txt > hc_passwords.txt`


### Options
- 