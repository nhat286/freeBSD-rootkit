// BAD SYSCALL HOOK USED FOR TESTING FUNCTION POINTER REDIRECTION.
//
// this syscall hook modifies the syscall function pointer to
// point to our hook function (new_sy_call).
// the syscall hook (new_sy_call) just calls the old syscall.
//
// NOTE XXX because the syscall function pointer is redirected to point
// to the module's function, which resides in the module's memory pages,
// when the module is unloaded, these pages can be paged out at
// anytime by the kernel. this means that it is desirable to restore
// the old sys call when the module is loaded (to prevent the
// system from becoming unstable when testing rootkit detection).
//
// NOTE XXX because this bad hijacker restores the syscall function
// pointer to point to the old syscall (for stability during testing),
// the hijack hook can only be detected when the module is in the kernel.

#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/pcpu.h>
#include <sys/syscall.h>
#include <sys/sysent.h>

static sy_call_t *old_sy_call = NULL;

// syscall hook.
static int
new_sy_call(struct thread *td, void *syscall_args) {
    return old_sy_call(td, syscall_args);
}

// function that is called when the module is loaded and unloaded.
static int
load(struct module *module, int cmd, void *arg) {

    switch (cmd) {
    case MOD_LOAD:

        // record the old syscall.
        old_sy_call = sysent[SYS_rmdir].sy_call;

        // redirect the syscall function pointer to point to the hook.
        sysent[SYS_rmdir].sy_call = new_sy_call;

        break;

    case MOD_UNLOAD:

        // restore the function pointer to point to the old syscall.
        // this ensures the stability of the system during detection testing.
        sysent[SYS_rmdir].sy_call = old_sy_call;

    default:
        break;
    }

    return (0);
}

/* The second argument of DECLARE_MODULE. */
static moduledata_t bad_hijack_1_mod = {
    "bad_hijack_1",       /* module name */
    load,                 /* event handler */
    NULL                  /* extra data */
};

DECLARE_MODULE(bad_hijack_1, bad_hijack_1_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
