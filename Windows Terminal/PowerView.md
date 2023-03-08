https://gist.github.com/HarmJ0y/184f9822b195c52dd50c379ed3117993

### Usage



### Useful Examples
- `Get-NetComputer -fulldata | select operatingsystem` - get a list of operating systems on the domain
- `Get-NetUser | select cn` - get a list of users in the domain
- `Get-NetUser | ?{_$.memberof -match 'Domain Admins'`


### Options
- 