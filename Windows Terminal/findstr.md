text search with regex capability

`findstr hello there test.txt` : find hello or there in file
`findstr /s c/:"hello there" *.*` : find "hello there" in dir and all subdirs

`/i` : insensitive
`/s` : recursive search
`/n` : display line number
`/l` : search as a literal
`/r` : search as regex
`/c:STRING` : search for STRING as a literal
REGEX:
	`^.*[0-9]$` : beginning, any, repeat, range, end
	