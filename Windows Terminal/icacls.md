check and set directory/file privileges

`icacls C:\WINDOW|DIRECTORY\OR\FILE.exe /grant Everyone:F`

`-grant GROUP:PERM`: Groups - Everyone,... Perms: F
Basic PERMs: (F) Full access, (M) Modify access, (RX) Read and execute access, (R) Read-only access, (W), Write-only access
Advanced PERMs: (D) Delete, (RD) Read data/list directory, (WD) Write data/add file, (AD) Append data/add subdirectory