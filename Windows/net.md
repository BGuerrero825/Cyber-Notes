### Usage
lists or manage objects (users and groups) in a network, given a specific object type

`net OPTION`

### Useful Examples
- `net user /domain` - lists all users in the domain 
- `net user barry.jackson /domain` - gives info about a specific user 
	- Often fails to show more than 10 groups, if member of many
- `net group "Tier 1 Admins" /domain`
- `net accounts /domain` - get password policy
- `net user /add Babu password_shhhh` : (as admin) add local user
- `net localgroup Administrators Babu /add` : (as admin) add Babu to admin group
	- `/del` : to remove user
- `net help` : more options for net

### Options
- `ACCOUNTS | COMPUTER | CONFIG | CONTINUE | FILE | GROUP | HELP | HELPMSG | LOCALGROUP | PAUSE | SESSION | SHARE | START | STATISTICS | STOP | TIME | USE | USER | VIEW `