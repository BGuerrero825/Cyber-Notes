Visualize the AD environment in a graph format with interconnected nodes.
Phase 1: use an initial foothold to loudly enumerate the network and exfiltrate AD network data.
Phase 2: use the exfiltrated data locally to map out and efficiently plan and then execute a reattack of the network.

# Sharphound
The enumeration tool of Bloodhound
### Sharphound.ps1 
PowerShell version, good with RATs since it can be injected direct into memory, evading scans
### Sharphound.exe 
Windows binary executable, the most common script
### AzureHound.ps1
Version for running on Azure. Generated paths for the config of Azure Identity and Access Management

**Sharphound and Bloodhound versions should match for best results**

We can use [[runas]] on a controlled Windows machine, that is not domain joined, to feed AD creds and point it to the DC to run a sweep. In provided example, we are provided an authenticated windows jump box.

`Sharphound.exe --CollectionMethods <Methods> --Domain za.tryhackme.com --ExcludeDCs`
- --CollectionMethods, "Default" and "All", rspecifies what information to collect. Data is then cache'd for reruns
- --Exclude DCs, don't scan the DC as this will likely raise alerts
- Others: https://bloodhound.readthedocs.io/en/latest/data-collection/sharphound-all-flags.html

Copy over to local desktop with [scp] 
`scp kimberley.smith@THMJMP1.za.tryhackme.com:/Tools/20230307145128_BloodHound.zip ~`

# Bloodhound Import
1. Requires neo4j to run, ensure this is installed, then run it `neo4j console start`
2. In another terminal `bloodhound --no-sandbox` 
	1. default creds `neo4j:neo4j`, may need to navigate to http://localhost:7474 to change
3. Drag and drop .zip file onto Bloodhound GUI

# Attack Paths
Type in an object name
### Node Info
Returned from AD databases
- Overview - Provides summary information such as the number of active sessions the account has and if it can reach high-value targets.
- Node Properties - Shows information regarding the AD account, such as the display name and the title.
- Extra Properties - Provides more detailed AD information such as the distinguished name and when the account was created.
- Group Membership - Shows information regarding the groups that the account is a member of.
- Local Admin Rights - Provides information on domain-joined hosts where the account has administrative privileges.
- Execution Rights - Provides information on special privileges such as the ability to RDP into a machine.
- Outbound Control Rights - Shows information regarding AD objects where this account has permissions to modify their attributes.
- Inbound Control Rights -  Provides information regarding AD objects that can modify the attributes of this account.

### Analysis
Custom Bloodhound scripts to help enumeration. Use these to find jumping off points to Admin / DC

### Edge Filtering
Can be utilized to remove / add relationships into the graph, tailorable to intended attack vector