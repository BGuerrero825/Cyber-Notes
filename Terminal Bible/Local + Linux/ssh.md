ssh **user**@**IP** -p **port**

ssh kali@192.168.199.50 -p 2222

* * *
## Download a file
ssh student@192.168.199.50 "cat > remote" < file

## Send a file
ssh ajw@192.168.199.50 "cat remote" > copy