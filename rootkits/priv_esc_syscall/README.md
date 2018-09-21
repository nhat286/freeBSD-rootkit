* Have a look at ch01/sc\_example, which has now been updated to show syscall()'s behavior upon success and failure
* My current implementation now successfully imitates the behavior of syscall()'s behavior upon success and failure
    * Current implementation will act as if ENOSYS happened (syscall does not exist) when called with incorrect password
    * Same message is printed to the controlling terminal
    * Same message is printed to kernel's dmesg
    * Same return number and errno is returned to the invoking file
    * Reason why I did this is because detection scripts can create C files that call syscalls (with different numbers) and then check behaviors
    * If the syscall is invoked with the correct password, then we can add additional functionality.

* TODO:
    * figure out a way to send a SIGABRT or core dump signal from kernel to user space
    * may require forking and then raising the signal to closely mimic the natural behavior
    * problem is that user space functions or user space include files are different
        * research more into https://github.com/freebsd/freebsd/blob/master/sys/kern/kern_sig.c
        * research more into the code execution of userland signal.h's raise (and find corresponding kernel implementations)
    * use `man 2 unlink` to remove all of our files once they've been loaded
        * problem is C's unlink will only delete the file once the last reference to it is deleted.
        * this is not possible since the module is resident in memory, which will keep the last reference
        * plain old rm will work and remove the file, but will it cause problems when the kernel module needs to be paged out??? need to research more on this
    * persistent module loading
    * use kern\_execve of /sys/sys/syscallsubr.h to execve to su shell
        * td arg (struct thread) will be the current thread
        * for examples of how kern\_execve is executed:
        * https://github.com/freebsd/freebsd/blob/master/sys/kern/kern_exec.c
        * for the defintion of the struct image_args argument (image of new process to be executed), including argv, filename, envp, fd table, etc:
        * https://github.com/freebsd/freebsd/blob/master/sys/sys/imgact.h
        * the functions within the imgact.h file are defined in /sys/kern/kern_exec.c (the previous file)
        * we need to use the functions in kern_exec.c to set up the image structs (struct image_args and struct image_params).
        * kern_exec.c also contains the function sys\_execve(), which is the entry point of this syscall.
        * our module essentially has to do those steps (with quite a few changes) to set up the correct args for su shell before kern\_execve su shell
        * another argument to kern\_execve is struct mac, which is defined here https://github.com/freebsd/freebsd/blob/master/sys/sys/mac.h
        * struct mac refers to Mandatory Access Control MAC https://en.wikipedia.org/wiki/Mandatory_access_control
    * another problem: if a detection script will register their own syscall, then they would get 211 instead of 210 (which would reveal that we have been loaded).
        * this may mean that we have to instead edit the syscall table
        * the syscall entry of a pre-existing syscall within the syscall table will be edited so that the first argument is checked to see whether it has the correct password
        * if the arg passed isnt a password, then just call the default syscall handler
        * if the correct password is called, then call our syscall handler
            * calling our syscall handler should not result in issues since if our module is resident in memory, then the address jump will be valid
        * this entire sub task is super hard. leave it to the last
        * for detection, https://github.com/freebsd/freebsd/blob/master/sys/kern/sys_process.c (need to find its corresponding .h file) can be used to read /dev/kmem
        * https://github.com/freebsd/freebsd/blob/master/sys/kern/kern_syscalls.c may help to see how syscalls are registered and deregistered
