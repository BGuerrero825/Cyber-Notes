### Connect to Network
Try pinging the DC (should work if auto-connected via AttackBox)
DNS is required to resolve hostnames to IPs on Windows Network.
`systemd-resolve --interface breachad --set-dns DC_IP --set-domain za.tryhackme.com` to configure DNS
`nslookup thmdc.za.tryhackme.com` to test DNS, which should resolve the DC's IP
### On Kali
1. Download config file, drop into Kali VM
2. `sudo openvpn VPN_NAME.ovpn`
3. (Ethernet Port symbol = NetworkManager ) Edit Connections -> Network Connection 1 -> IPv4 Settings -> Additional DNS servers ->`DC_IP_ADDR, 1.1.1.1` (ones' is for standard DHCP for internet access)
4. `sudo systemctl restart NetworkManager`
5. nslookup `DOMAIN.NAME.HERE.com`