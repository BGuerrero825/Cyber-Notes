### Usage
lists or manage objects in a network, given a specific object type

`net OPTION`

### Useful Examples
- `net user /domain` - lists all users in the domain 
- `net user barry.jackson /domain` - gives info about a specific user 
	- Often fails to show more than 10 groups, if member of many
- `net group "Tier 1 Admins" /domain`
- `net accounts /domain` - get password policy

### Options
- 