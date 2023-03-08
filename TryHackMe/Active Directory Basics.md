
Active Directory: centralized administration of common components on a windows network in a single repository. Domain Controller - is the server running the AD service.
- Active Directory Domain Service (AD DS) - a service that acts as a catalogue for all objects on the network. Users, groups, machines, printers, shares, etc.
- [[AD DS Data Store]]
- **Users** - "security principal" objects, they can be assigned privileges over "resources" (files, printers, etc)
	- Service users will only have privileges needed to run their specific service
	- Machines: security principal objects, computers that join AD and are assigned an account like a regular user. Usually local admin on the computer.
	- Passwords are auto-rotated and are 120 random characters. Account are recognizable, account name is the PC_NAME+$ (DC01->DC01$)
- **Security Groups**: Set of permissions for various users, some are created by default
	- Domain Admins: privilege over entire domain, can admin on any computer, including DC
	- Server Operators: admin over the DC, cannot change admin group memberships
	- Backup Operators: Can access any file, ignoring perms
	- Account Operators: create or modify other account in domain
	- Domain Users
	- Domain Computers
	- Domain Controllers
- Full information: [https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups](https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/active-directory-security-groups)  

# [[AD Users and Groups]]
  
# Active Directory Users and Computers
To configure AD, log into DC box and run "Active Directory Users and Computers"
Objects are organized into Organizational Units (OUs), users can only belong to 1 at a time. It will typically imitate the business structure. 
- Default OUs
	 - Built-in: default groups available to any windows host
	- Computers: new machines joining the network move here by default, then can be moved
	- Domain Controllers: contains all DCs in the network
	- Users: Default users and groups in domain-wide context
	- Managed Service Accounts: accounts used by services
- OU's: apply policies which include specific configs by role, each user is exclusive
- Security Groups: grant permissions over resources, ALLOWS things, users are not exclusive.

  
# Managing Users
- Delete: Top toolbar - View, Advanced Features, then right click and Delete on thing
- Delegate: Right click, and delegate on the group you want to give control over, type in user name of the person to grant that control
	1. `Set-ADAccountPassword sophie -Reset -NewPassword (Read-Host -AsSecureString -Prompt 'New Password') -Verbose` - reset the specified user password, provide input command line.
	2. `Set-ADUser -ChangePasswordAtLogon $true -Identity sophie -Verbose` - force password reset at next user login

  
# Managing Computers
Workstations: User stations, no privileged users should login here
Servers: provide services to users
Domain Controllers: sensitive, contain hashed passwords for all user accounts
  

# Group Policies
Managed in the Group Policy Management tool
Group Policy Objects (GPO), a collection of settings that can be applied to OUs, comprised of computers or users, to set a baseline on machines / identities.
GPO are linked to OUs through the tool, GPOs also effect sub-OUs that they attach to.
Security Filtering: filters down a GPO to only apply to specific users or computers in an OU, by default a GPO applies to all Authenticated users (everyone)
The Settings tab includes the actual contents of the GPO and lets us know what specific configurations it applies
Example configuration: 
Right click GPO -> Edit -> Computer Configurations -> Policies -> Windows Setting -> Security Settings -> Account Policies -> Password Policy

### GPO Distribution
GPOs are distributed via the network share `SYSVOL` on the DC. All users have access in order to sync their GPO. `C:\Windows\SYSVOL\sysvol\` on the DC.
To force an update (as default syncs are infrequent) `gpudate /force`

### Creating and Editing GPO Practice

# Authentication Methods
In Windows domains, all creds are stored on a DC using the following auth methods.
- Kerberos: Default in new domains
- NetNTLM: Legacy (obsolete), kept for compatibility 

### Kerberos
1. User sends their username and timestamp encrypted with a User Hash (password derived key) to the Key Distribution Center (KDC) running on the DC
2. KDC sends back a Ticket Granting Ticket (TGT), which the user will use to request additional tickets for access to additional services (so the user isn't constantly sending over its creds on the network) along with a session key for generating consequent requests. ![[Pasted image 20230303153232.png]]
	1. The user cannot decrypt the TGT because it is encrypted with a `krbtgt` hash only on stored on the DC. The TGT contains the Session Key, which the KDC can decrypt, and therefore has no need to store it.

3.  The user tries to connect to a network service (share, website, database) and sends a Session Key encrypted username + timestamp, along with the TGT and a Service Principal Name (SPN) to request a Ticket Granting Service (TGS) from the KDC. The TGS allows access only to the service and server name the user requests access to.
4. The KDC sends back a TGS, encrypted using a key derived from the Service Owner Hash which the user/computer running the service also has, along with a Service Session Key to use with the service. The TGS contains a copy of the Service Session Key so the Service Owner can decrypt and use it.
![[Pasted image 20230303153311.png]]
6. The user then sends their username and timestamp to the service with the TGS, which the service uses to validate the session.
![[Pasted image 20230303153325.png]]

### NetNTLM
1. Users send auth request to a service
2. Service sends a random number "challenge"
3. Users sends their combined password hash / challenge as a Response.
4. The service forwards the response and original challenge to the DC
5. DC also has user password hash, and recalculates a Response with the password hash / challenge, then checks this against the service's result
6. DC sends an allow/deny to the service, the service then forwards this to the user and begins a session.

# Trees, Forests and Trusts
Tree: supports domains as "branches" from an original domain, allowing for unique DCs and policies in the branched subdomains. Ie. thm.local becomes us.thm.local and uk.thm.local. New level of admin introduced called "Enterprise Admin"
Forest: a group of trees which interact via Trust Relationships. Ie. thm acquires corpa, creating a link between the domains thm.local <---> corpa.local
Trust Relationship: authorizes users from one domain tree to another 
	- One-way Trust (Directional): domain "Fileserver" Trusts domain "Nashua Branch" and so nashua has Access to the file server
	- Two-way Trust (Transitive): Mutual Access and Trust, this is default

# Domain Services
Defaults: 
-   LDAP - Lightweight Directory Access Protocol; provides communication between applications and directory services
-   Certificate Services - allows the domain controller to create, validate, and revoke public key certificates
-   DNS, LLMNR, NBT-NS - Domain Name Services for identifying IP hostnames

# Cloud AD
Translation table \\/
**Windows Server AD** | **Azure AD**
LDAP  |  Rest APIs
NTLM  |  OAuth/SAML
Kerberos  |  OpenID
OU Tree  |  Flat Structure
Domains and Forests  |  Tenants
Trusts  |  Guests