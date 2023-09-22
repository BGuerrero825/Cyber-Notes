

# usage
- `6x` - to delete first 6 chars of a line
- `d` - delete the rest of the line
- `:set number`
- `:%s/SEARCH_STRING/REPLACEMENT_STRING/g` : replace all
	- `%` : search all lines
	- `s` : substitute 
	- `g` : "global", tells vi to continue searching
- Recording via `q` + `ANY_LETTER`, quit via `q` again, replay via `@LETTER`
- `0`: (zero) to go to beginning of line
- `:r !TERMINAL_COMMAND` : to ‘read’ terminal output to file
- `CTRL-R` : redo