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

