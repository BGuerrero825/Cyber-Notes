query the registry

`reg query hkcu\software\microsoft\...`
`reg delete PATH /va`
`reg add PATH /v OneDrive /t REG_SZ /d VALUE_PATH` : add OneDrive key to PATH  
`reg export REG_PATH FILE_NAME` : export registry key to file (can be transferred to a new machine with `reg import ...`)
`reg load HKU\OTHER_USER C:\Users\OTHER_USER\ntuser.dat` : load other users registry into new hive HKU

`/va` : remove all values from key
`/v` : name the value
`/t` : specify data type
`/d` : specify data path
