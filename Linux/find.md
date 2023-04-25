search system for files / directories, "recursive" ls

`find SOURCE_PATH -iname "WILDCARDS+STRINGS"` (\*,?,^,)
`find ~ -iname "*flag.txt"`
`find / -perm -u=s -type f 2>/dev/null`

`-iname "WORD": `case insensitive "in name" regex match
- \*, wildcard, any amount
- ?,  wildcard, one occurrence
- [], encapsulate char series (`[tmp/]*`)
`-name WORD:`exact name match (wildcard allowed)
`-type f,d:`search files or directories only
`-perm -u/g/o=r/w/x`: file has read, write, exec permissions for whatever user
`-perm -0777:` file with all permissions to all users (see below)
`-user USERNAME`: files for user
`-mtime (-/+)TIME_IN_DAYS: `file last modified, in days (-/+ for less than/greater than)
`-atime (-/+)TIME_IN_DAYS:`file last accessed
`-cmin (-/+)TIME_IN_MIN`: file last changed, in min
`-amin (-/+)TIME_IN_MIN`: file last accessed
`-size (+)NUM`: file less than size, suffix of M, k, G for units (+ for greater than)
`2>/dev/null`: pipes all errors to nowhere

#### -perm guide
first bit: 4=SUID, 2=SGID, 1=Sticky
`perm 4771` = no prefix, exact match of given mode in permissions
`perm -4000` = tac, all bits set in mode are set in permissions
`perm /4777` =slash, any bits set in mode are set in permissions