

`awk -F: '($2 != "x") {print}' /etc/passwd`
(print off any passwords stored in the passwd file)