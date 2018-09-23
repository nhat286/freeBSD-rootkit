* Have a look at ch01/sc\_example, which has now been updated to show syscall()'s behavior upon success and failure
* My current implementation now successfully imitates the behavior of syscall()'s behavior upon success and failure

* TODO:
    * another problem: if a detection script will register their own syscall, then they would get 211 instead of 210 (which would reveal that we have been loaded).
        * this may mean that we have to instead edit the syscall table
        * the syscall entry of a pre-existing syscall within the syscall table will be edited so that the first argument is checked to see whether it has the correct password
        * if the arg passed isnt a password, then just call the default syscall handler
        * if the correct password is called, then call our syscall handler
            * calling our syscall handler should not result in issues since if our module is resident in memory, then the address jump will be valid
        * this entire sub task is super hard. leave it to the last
        * for detection, https://github.com/freebsd/freebsd/blob/master/sys/kern/sys_process.c (need to find its corresponding .h file) can be used to read /dev/kmem
        * https://github.com/freebsd/freebsd/blob/master/sys/kern/kern_syscalls.c may help to see how syscalls are registered and deregistered
