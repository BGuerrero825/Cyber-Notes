check and set directory/file privileges

`icacls C:\WINDOWS_DIRECTORY\OR\FILE.exe /grant Everyone:F`
`icacls * | findstr (M)*` - list all in dir, find all modifiable

- `/grant GROUP:PERM` : 
	GROUPS : Everyone, Administrators, etc.
	Basic PERMs : (F) Full, (M) Modify, (RX) Read and execute, (R) Read, (W) Write 
	Advanced PERMs : (D) Delete, (RD) Read data/list dir, (WD) Write data/add file, (AD) Append data/add subdir
	**WDAC** : Write Dir Access Control, good pivot point to modify account perms
- `/grant:r ...` : "replace" existing perms with supplied perm only
- `/deny ... `
- `/t` : recursive
- `/c` : ignore errors
- `/l` : execute on link instead of target


<details>
<summary>Full Permission Options</summary>

**iCACLS inheritance settings:**

-   (OI)  —  object inherit;
-   (CI)  —  container inherit;
-   (IO)  —  inherit only;
-   (NP)  —  don’t propagate inherit;
-   (I)  — permission inherited from the parent container.

**List of basic access permissions:**

-   D  —  delete access;
-   F  —  full access;
-   N  —  no access;
-   M  —  modify (includes ‘delete’);
-   RX  —  read and execute access;
-   R  —  read-only access;
-   W  —  write-only access.

**Detailed permissions:**

-   DE  —  delete;
-   RC  —  read control;
-   WDAC  —  write DAC;
-   WO —  write owner;
-   S  —  synchronize;
-   AS  —  access system security;
-   MA  —  the maximum allowed permissions;
-   GR  —  generic read;
-   GW  —  generic write;
-   GE  —  generic execute;
-   GA  —  generic all;
-   RD  —  read data/list directory;
-   WD  —  write data/add file;
-   AD  — append data/add subdirectory;
-   REA  —  read extended attributes;
-   WEA  —  write extended attributes;
-   X  —  execute/traverse;
-   DC  —  delete child;
-   RA  —  read attributes;
-   WA  —  write attributes.

</details>