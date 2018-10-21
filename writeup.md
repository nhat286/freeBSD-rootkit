# Final Rootkit Writeup
__Members of Group 99:__
```
 zXXXXXXX 
 zXXXXXXX
 z5137455 Minh Thien Nhat Nguyen
 z5087077 Ka Wing Ho
```

## Installation

Answer: Our rootkit is a loadable kernel module that hijacks a preexisting syscall to perform privilege escalation if a specific set of arguments is passed in. If not, then the hijacked syscall would mimic the original syscall to minimise the possibility of detection. For our current implementation, the hijack victim syscall will be `rmdir`, which is syscall number 137. 


`sys/pcpu.h` provides a definition of curthread which is a pointer to the struct thread of the currently executing thread. Struct thread has a member called `td_proc` which is a pointer to the associated process of the currently running thread. Struct proc has a pointer to struct `sysentvec` which is a structure containing all of the syscall entries and associated metadata of the system. Struct sysentvec has a member called `sv_table` which is an array of struct `sysent`s. This `sv_table` array is indexed using syscall numbers. Struct `sysent` contains a function pointer to the system call handler/function for a specific syscall number, and it also contains associated metadata for the system call such as number of arguments.


Upon loading the kernel module using `kldload`, our current implementation saves the current syscall handler for the hijacked victim in a static function pointer called `old_sycall`. It then redirects the syscall handler to point to `new_sy_call`. The kernel module is then unloaded using `kldunload` as it has served its purpose which is to override the syscall function pointer to our own malicious function.


When the victim syscall (rmdir syscall) is invoked, the `new_sy_call` function first invokes the original syscall using the previously saved `old_sy_call` function pointer while passing it the same args. If the return value is not 0 (which indicates that the syscall was not successful), then we return the return value from the original syscall as the system call arguments may have been mapped to invalid pages if the original syscall failed. If not, then the argument pointer is cast to a struct `sc_args` pointer which represents the arguments of a struct. If the path member of this argument struct matches a predefined password, then we escalate the current thread and its associated process to root. The return value from the original system call invocation is returned to mimic the real behaviour of the original syscall. 

#### Changes made since midpoint

__For final rootkit version__

Answer: Our rootkit is a loadable kernel module that hijacks a preexisting syscall to perform privilege escalation if a specific set of arguments is passed in. If not, then the hijacked syscall would mimic the original syscall to minimise the possibility of detection. For our current implementation, the hijack victim syscall will be `openat`, which is syscall number 499. 


`sys/pcpu.h` provides a definition of curthread which is a pointer to the struct thread of the currently executing thread. Struct thread has a member called `td_proc` which is a pointer to the associated process of the currently running thread. Struct proc has a pointer to struct `sysentvec` which is a structure containing all of the syscall entries and associated metadata of the system. Struct sysentvec has a member called `sv_table` which is an array of struct `sysent`s. This `sv_table` array is indexed using syscall numbers. Struct `sysent` contains a function pointer to the system call handler/function for a specific syscall number, and it also contains associated metadata for the system call such as number of arguments.


Upon loading the kernel module using `kldload`, our current implementation mallocs a memory region of size 256 bytes to store the hook function. Then, it writes a jump instruction after the first 3 bytes (setting up the stack with `push ebp; mov ebp, esp;`) to that memory region. The kernel module is then unloaded using `kldunload` as it has served its purpose which is to inject an inline hooking inside the syscall to jump to our own malicious function.


When the victim syscall (openat syscall) is invoked, the syscall function first sets up the stack with `push ebp; mov ebp, esp;`, and jumps to our malicious function in memory. Then, the new function continues setting up the stack to keep the stack state valid and consistent, then do a `ret` to the original syscall to save the instruction pointer to our new function onto the stack. The openat syscall executes normally, and at the end returns to our function in memory with the saved instruction pointer on the stack. The new function will then escalate if the argument to the syscall matches the specific string, then returns with the return value of `openat` to mimic the real behaviour of the original syscall.

## Privillege Escalation


The escatate function takes in a struct thread pointer and escalates the thread and its associated process to root by modifying its struct ucred, which is a pointer to the credentials struct of this thread and its process. This escalates the process of the currently executing install script to root. After the script process terminates and returns to the controlling tty (terminal), the controlling tty is escalated to root as well due to a kernel optimization. This is because when the install process is forked and executed as a child process of the controlling tty, the ucred struct is not duplicated by the kernel if the child process isn’t explicitly forked and launched with the option to explicitly assume the identity of a user, hence the child and parent processes share the same ucred struct. This means that modifying the ucred struct of the child process also modifies the permissions of the parent process.


When the rmdir syscall is invoked successfully (with a retval of 0), and if the syscall has the secret password as the path argument (such as `mkdir PRIV_ESC_PASSWD && rmdir PRIV_ESC_PASSWD`), then the child process (the install program) is escalated to root. When the child process (the install program) returns then the controlling tty will have root privileges as well.

#### Changes made since midpoint

__For final rootkit version__
When the openat syscall is invoked (by running `touch` or `mkdir`) with the path argument that matches the secret password (such as `mkdir *3f5b1 && rmdir *3f5b1`), then the child process (the install program) is escalated to root. When the child process (the install program) returns then the controlling tty will have root privileges as well.

## Stealth 


Since the hijacking is done when the kernel module is loaded, there is no need for the kernel module to reside within the kernel after it has achieved its purpose. It can then be safely unloaded immediately using kldunload, leaving no trace of the rootkit module in either kldstat or within the kernel list for kernel modules.


Also, since the privilege escalation is done without invoking `system(su);` or other commands that log activities to `/var/log/*`, there is no need to perform any cleanup with regards to the log files.

#### Changes made since midpoint

## Bonus Marks 
Our rootkit currently does not attempt any bonus marks.

## Rootkit Design Decisions
(do we still need this ? hmmm) 
```
```
![RUN](https://vgy.me/STqsgy.png)
```
```
```
NOTES: CHANGES MADE SINCE MIDPOINT
- we no longr use mkdir() with a long password string
- we changed it to use touch() instead (check the __For final rootkit version__)
- ~~(we clean up the syscall table so the pointers look unchanged (but the opcodes of the syscall have changed))~~
- Technically, we didn't touch the syscall table, we instead hijacking the syscall instructions itself, so the table is clean, but not the opcodes.
    - this is also how we can detect our midpoint rootkit 
```


## Detection Tactics ~(detection methods and how)~

(CHANGE THE STAGE4.SH BEAUSE PERL IS NOT INSTALLED)

#### Inspecting the integrity of the syscall table
- use johnsons detections kernel modules
- check if syscall entries exactly match
   - checks if all the ptrs in the syscall table the same
   - it should always be consisntent 
- checks for processes tidhashtable
- runq (couldnt get it to work but put lots of effort into it)
i
the way his thing works is that if the kernel is dirty then the lkm will fail to load
we simply write a userland to run modfind and this will tell us if the system is infected 

#### Comparing thread count with pidhashtable

####  High-level detection
We remain careful with this sort of detection as false positives are inherently high (especially since the spec mentioned that there are other processes running to simulate a real system)

Since most rootkits will have to compile their kernel objects somehow (some groups have written in their midpoints submissions that they will have make files), there is a chance that the local `cc` compiler willbe used, we check that the access time has not changed since birth, if it has that increases the rootkit score

During escalation the spec mentions that some commands will be run, we predict these commands will be `ls`, `id` and `whoami` therefore we saved the access times of these binaries pre-escalation, and compare with these binaries post-escalation. On a clean host these should not change. 

Although fairly trivial, we also do some signature detection, by bringing a file with hashsums of popular binaries to trojan as well as the kernel file, to catch any teams who meddle in the userland.



#### Comparing the syscall table against a saved snapshot of a clean syscall table
Deep and Eric wrote a syscall\_dumper loadable kernel module `opcodes.ko` which would print out the syscall table rows to `dmesg`, this dumped table is then parsed with a statically-linked userland program `checker`, and will return whether inline hooking instructions are present in the in-memory syscall table. 

## Rootkit Detector Design Decisions
- we saw lots of other teams doing the bonus marks
- also some teams were relying very heavily on the book methods (some of them are not entirely hiding the rootkit)
- therefore we try to use out-of-the-book methods to catch sloppy teams
- we also do high-level behaviour and signature detection just to be well-rounded
- our detection doesn't focus very much on signature ie:
    - trojan'ed binaries
    - searching for suspicious files
 simply because most teams are not doing userland rootkits, therefore we shifted our focus more on kernel-level detection

- the `detect.sh`script is actually just a dispatcher script that will call 5 other scripts in stages
- the detect script keeps track of state via spawned daemons as well as a startup script in `/usr/local/etc/rc.d/` which will respawn daemons and restore important files after reboot 
- it is also made to detect if the daemons or files are missing which will contribute to an early detection if any rootkit teams try to mess with our state 
