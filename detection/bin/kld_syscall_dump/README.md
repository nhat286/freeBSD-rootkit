* Store clean syscall instructions in file called 'log'
* Use opcode.ko to dump current syscall instructions, and run `cat /var/log/messages > mes`
* Compile `checker.c` with `cc checker.c -static -o checker` and run
* Check return of `checker` program
