## `alias ...`

- `ll=ls -al`
- `mkdir='mkdir -p'`
- `..='cd ../'`
- `cls='clear'`
- `htblab='openvpn ~/Documents/noobsecdotnet.ovpn'`
- `myip="ip -c a | grep -w 'inet' | cut -d'/' -f 1"`
- `pyserv="python3 -m http.server"`
- `smbsrv="impacket-smbserver"`

write to `~/.zshrc` for persistent aliases
`source ~/.zshrc` to reload shell environment