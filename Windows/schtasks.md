`schtasks`
`schtasks /create /sc weekly /d mon /tn runme /tr C:\runme.exe /st 09:00`
`schtasks /delete /tn runme`
`schtasks /query /tn run /fo list`

`/sc INTERVAL` : set task frequency 
	 MINUTE, HOURLY, DAILY, WEEKLY, MONTHLY, ONCE, ONSTART, ONLOGON, ONIDLE, ONEVENT
`/d` : day of the week
`/tr` : taskrun, path of file to run
`/tn` : taskname, declare task name
`/st` : start time
`/ru USERNAME` : run as USERNAME