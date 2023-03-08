user ids and info exposed in a url header, which can then be manipulated
It might be coded in base64, use CyberChef or `https://www.base64decode.org/`
or
`https://crackstation.net/` on hashed urls

Ex. Make 2 accounts on a website, if one is accessible while being logged into the other by url manipulation, then there is no session check and there is IDOR (/usr/details?user_id=189172)

