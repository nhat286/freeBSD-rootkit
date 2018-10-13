// BAD SYSCALL HOOK USED FOR TESTING FUNCTION POINTER REDIRECTION.
//
// memory is allocated during module load. the instruction bytes of
// new_sy_call (our hook) is copied to the allocated memory.
// the syscall function pointer is then redirected to point to the
// allocated memory.
//
// for testing and demonstration purposes, the hook just calls the old
// syscall implementation.
//
// NOTE XXX because the syscall hook (in the allocated memory region)
// depends on a variable (old_sy_call) that resides in the module's
// memory pages, when the module is unloaded, these pages can be paged out
// at anytime by the kernel. this means that it is desirable to restore
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
#include <sys/types.h>
#include <sys/malloc.h>

static sy_call_t *old_sy_call = NULL;
static char *malloc_addr = NULL;

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

        // malloc must not cause this process to be to put to sleep (NO_WAIT),
        // so it must use system reserve (so that the request can be satisfied
        // without this process being put to sleep).
        // the malloc region surprisingly has execute permissions.
        malloc_addr = malloc(256ul, M_TEMP, M_NOWAIT | M_USE_RESERVE);
        if (malloc_addr == NULL) {
            return (1);
        }

        // copy the instruction bytes in new_sy_call (the hook) to the malloc region.
        char *new_sy_call_addr = (char *)new_sy_call;
        for (unsigned int i = 0; i < 256; i++) {

            // if we hit a page boundary, break out because
            // the permissions may not be the same across different pages.
            if ((unsigned int)(new_sy_call_addr + i) % PAGE_SIZE == 0) {
                break;
            }

            malloc_addr[i] = new_sy_call_addr[i];
        }

        // redirect the syscall function pointer to point to the
        // hook in the malloc memory.
        sysent[SYS_rmdir].sy_call = (sy_call_t *)malloc_addr;

        break;

    case MOD_UNLOAD:

        // free the allocated memory (to prevent leaks and for testing stability).
        if (malloc_addr != NULL) {
            free(malloc_addr, M_TEMP);
        }

        // restore the function pointer to point to the old syscall.
        // this ensures the stability of the system during detection testing.
        sysent[SYS_rmdir].sy_call = old_sy_call;

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
