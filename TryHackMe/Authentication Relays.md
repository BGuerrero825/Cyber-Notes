Includes attacks against broader network authentication protocols, staged from our device.

# Server Message Block
NetNTLM authentication is used by [[SMB]] on Windows. Old versions vulnerable to cred dumping and remote code exec.
- Intercept challenge to crack password
- stage a MITM, giving us an active session

# LLMNR, NBT-NS, WPAD
Use [[responder]] to intercept an NTLM challenge. It poisons the response during NetNTLM auth, making the client speak to the attacker. Tries to poison these broadcasting protocols
- LLMNR: Link-Local Multicast Name Resolution
- NBT-NS: NetBIOS Name Server
- WPAD: Web Proxy Auto-Discovery
Tries to win a race condition and so usually must be connected locally (tries to respond before actual service it is impersonating). 

1. sudo responder -I tun0` to wait for an incoming auth request
2. Copy the receive hash to a file
3. `hashcat -m 5600 <hash file> <password file> --force` to attempt to crack the hash using the provided file