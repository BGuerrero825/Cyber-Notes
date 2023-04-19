### Usage
text editing on a stream of text
`echo "Change this" | sed 's/Change/Changed/'` -> `Changed this`

### Useful Examples
- `sed 's/hello/goodbye!/g' hello.txt > goodbye.txt` - replace all occurrences of hello with goodbye
	- `sed '2 s/hello/goodbye!/g' hello.txt > goodbye.txt` - only perform replace on second line

### Options
- 