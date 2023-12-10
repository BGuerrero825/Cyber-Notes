-  `powershell -ep bypass`, force through execution policy restriction

`Get-Module -ListAvailable`  
`Import-Module ...`  
  
`New-Object System.DirectoryServices.DirectorySearcher` = `[adsisearcher]`
`fl *` = `Format-List`, * is format all columns??  
  
### .NET in Powershell  
`\[diagnostic.process\]::GetProcesses()` .NET method is roughly equivalent to the `PS Get-Process` cmdlet. 
- the \[\] segment signifies the .NET Framework namespace and class. "System." is assumed prior to the namespace.  
  
`%logonserver%` is the DC