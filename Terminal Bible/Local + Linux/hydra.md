Password Attack

`hydra -l USERNAME -P WORDLIST.txt SERVER SERVICE`

`hydra -l mark -P /usr/share/wordlists/rockyou.txt 10.10.74.138 ftp`

`-l USER`: provide login name
`-P WORDLIST`: specify password list
`-p PASS`: specify password
`-s PORT`: use to specify non-default ports
`-V, -vV:` verbosity, shows username and password combos tried
`-d`: debugging output
`-t`: threads, connections to target