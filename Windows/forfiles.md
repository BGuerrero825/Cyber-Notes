`forfiles /p C:\Windows /s /m notepad.exe /c "cmd /c echo @PATH"`

`/p` : path to begin search
`/s` : recursive
`/m FILE` : FILE to search for
`/c COMMAND` : command to execute