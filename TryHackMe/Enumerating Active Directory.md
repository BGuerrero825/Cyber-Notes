[[Connect to VPN]]

for RDP:
`xfreerdp /dynamic-resolution +clipboard /cert:ignore /v:THMJMP1.za.tryhackme.com /u:mandy.bryan` -> prompted for password

Once we have the first set of AD credentials, we can enumerate the system to reveal network setup, object, and structure. Looking for Priv Esc. 
Means of Enumeration:
-   The AD snap-ins of the Microsoft Management Console.  
-   The net commands of Command Prompt.
-   The AD-RSAT cmdlets of PowerShell.
-   Bloodhound.

# Requesting Credentials
We are provided a first set of creds for this example. Visit listed website, creds are generated. Use this to login to jump box for a "foothold". 
SSH or RDP into jump box, remember to specify domain when connecting via RDP

# Credential Injection
Credentials are often found before compromising a domain machine.

### [[runas]]
In depth enumeration and exploitation often requires acting like a Windows machine.
`runas.exe /netonly /user:DOMAIN\USERNAME cmd.exe`
Since the DC isn't used to validate, we can supply any password at the prompt (Note: run the initial cmd terminal as admin)

### DNS Setup
If on a Windows machine:
1. Verify/set DNS server (usually the DC)
	1. `$dnsip = "DC IP"`
	2. `$index = Get-NetAdapter -Name 'Ethernet' | Select-Object -ExpandProperty 'ifIndex'
	3. `Set-DnsClientServerAddress -InterfaceIndex $index -ServerAddresses $dnsip`
	4. `nslookup DOMAIN_NAME`
2. Verify injected creds are working by listing SYSVOL (all accounts can read it) from the DC, contains all GPOs and domain scripts. `dir \\DOMAIN_NAME\SYSVOL\`
Note: inputting domain name over the network will authenticate with Kerberos, while inputting IP can force an NTLM authentication

### Using Injected Creds
With AD credentials loaded into memory we can authenticate to some domain-joined services. Ex. MS SQL Studio will show local username on cmd, but on Log In will use injected AD credentials to authenticate to the network. Can also be used against NTLM web apps.

# Enumerations through Microsoft Management Console
How to add a Snap-In (if needed)
1.  Press **Start**
2.  Search **"Apps & Features"** and press enter
3.  Click **Manage Optional Features**
4.  Click **Add a feature**
5.  Search for **"RSAT"**
6.  Select "**RSAT: Active Directory Domain Services and Lightweight Directory Tools"** and click **Install**
RSAT (Remote System Administration Tools) should already be enabled on the jump box, now access Microsoft Management Console (MMC)
1. Run -> 'mmc' (doing it this way ensures that the runas.exe injected creds are used, not local)
2. Attach and config AD RSAT Snap-In:
	1. 1.  Click **File** -> **Add/Remove Snap-in**
	2.  Select and **Add** all three Active Directory Snap-ins
	3.  Click through any errors and warnings  
	4.  Right-click on each **Active Directory XYZ Snap-in**, Change Forest/Domain
	5.  Enter _za.tryhackme.com_ as the **Root domain** and Click **OK**
	6.  Right-click on **Active Directory Users and Computers** in the left-hand pane 
	7.  Click on **View** -> **Advanced Features**
MMC should now point and authenticate to the domain, so we can begin enumeration

### Users and Computers
We can now browse mmc for users by expanding "Active Directory Users and Computers" -> "za.tryhackme.com" -> "People"
We can go to Properties of each user and see useful things like "Member Of" for group membership.
Go to "Servers" or "Workstations" to see domain joined machines.
If we have permissions, we can use MMC to directly make changes like passwords, adding users to groups, etc.

**Look for**: Users, Groups, Servers, Workstations, IT, Admin, and potential controls over them

# Enumeration through Command Prompt
cmd can be useful when we have limited footholds (no RDP, PowerShell disabled/monitored, limited shell)
[[net]] - must be executed from a domain joined machine
`net /domain user` dumps all users in the domain
`net user barry.jackson /domain` gives info about a specific user
`net group /domain` -> `net group "Tier 1 Admins" /domain`
`net accounts /domain`, password policy gives us clues for a password spray attack


# Enumeration through PowerShell
[[PowerView]] 
If AD-RSAT tooling is installed, PowerShell will have access to the associated cmdlets (50+ of them). 
AD cmdlets: https://learn.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2022-ps

### Enumeration Commands:
`Get-ADUser -Identity gordon.stevens -Server za.tryhackme.com -Properties *`
- -Identity, account name to enumerate
- -Properties, filter fields to show (* is all)
- -Server, if not domain joined, this can point to DC
`Get-ADUser -Filter 'Name -like "*stevens"' -Server za.tryhackme.com | Format-Table Name,SamAccountName -A`
- filter for all "stevens" and print as a pretty table showing the two properties
`Get-ADGroup -Identity Administrators -Server za.tryhackme.com`
- specific group information
`Get-ADGroupMember -Identity Administrators -Server za.tryhackme.com`
- group membership information
`$ChangeDate = New-Object DateTime(2022, 02, 28, 12, 00, 00)` -> `Get-ADObject -Filter 'whenChanged -gt $ChangeDate' -includeDeletedObjects -Server za.tryhackme.com`
- gets all objects changed after a specific date, where Get-ADObject is a generic for users, groups, workstations, etc.
`Get-ADObject -Filter 'badPwdCount -gt 0' -Server za.tryhackme.com
- informs a password spray if any passwords are close/far from a lockout
`Get-ADDomain -Server za.tryhackme.com`
- gives info about the domain

`Set-ADAccountPassword -Identity gordon.stevens -Server za.tryhackme.com -OldPassword (ConvertTo-SecureString -AsPlaintext "old_pass" -force) -NewPassword (ConvertTo-SecureString -AsPlainText "new_pass" -Force)`
- If access allowed, will change a user's password as specified
`Set-ADUser -Identity kimberley.smith -Replace @{GivenName="kimberly.jones"}`
- If access allowed, will replace given property to listed value

NOTE: when listing objects, its helpful to use `... -Properties *` to get ALL info we can get on the object

# [[Bloodhound]]