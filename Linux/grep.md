`cat hi.txt | grep -i password`

-e, pattern
-i, ignore case
-E, regex pattern
- \[ABCa-z0-9\], match any of these
- | , or
 - ^, must start with
 - $, must end with
 - . , wildcard
 - ?, one or zero
 - \*, any amount
 - +, once or more
 - {n}, n times