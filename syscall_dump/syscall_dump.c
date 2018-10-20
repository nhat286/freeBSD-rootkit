#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/mutex.h>
#include <sys/sysproto.h>
// syscall(210, number?);
struct dump_args {
	int no;		/* number of syscalls */
};

/* System call to dump opcodes of syscall. */
static int
syscall_dump(struct thread *td, void *syscall_args)
{
    struct dump_args *uap;
    uap = (struct dump_args *)syscall_args;

    int j = 0;
    char *s = (char *) curthread->td_proc->p_sysent->sv_table[uap->no].sy_call;
    for (; j == 0 || (int ) s % 4096 != 0; s++) {
        printf("%x ", (unsigned int) (*s));
        j = 1;
    }

	return(0);
}

/* The sysent for the new system call. */
static struct sysent syscall_dump_sysent = {
	1,			/* number of arguments */
	syscall_dump		/* implementing function */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int
load(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		uprintf("System call loaded at offset %d.\n", offset);
		break;

	case MOD_UNLOAD:
		uprintf("System call unloaded from offset %d.\n", offset);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return(error);
}

SYSCALL_MODULE(syscall_dump, &offset, &syscall_dump_sysent, load, NULL);
