#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/pcpu.h>
#include <sys/mutex.h>
#include <sys/lock.h>
#include <sys/sx.h>

// returns 1 if each proc in the allproc list is in the pidhashtbl.
// returns 0 otherwise.
static int
allproc_in_pidhashtbl() {

    struct proc *p;
    sx_xlock(&allproc_lock);
    FOREACH_PROC_IN_SYSTEM(p) {
        PROC_LOCK(p);

        // if the process is currently being created,
        // it may not have been completely initialized yet.
        // XXX
        // it might be possible that rootkit processes may hide themselves
        // from being probed by setting their p_state to PRS_NEW.
        if (p->p_state == PRS_NEW) {
			PROC_UNLOCK(p);
			continue;
		}

        // check that each proc in the allproc list is in the pidhashtbl
        struct proc *found = NULL;
        LIST_FOREACH(found, PIDHASH(p->p_pid), p_hash) {
            if (found != NULL && found->p_pid == p->p_pid) {
                // XXX
                // it might be possible that rootkit processes may hide themselves
                // from being probed by setting their p_state to PRS_NEW.
                if (found->p_state == PRS_NEW) {
                    found = NULL;
                }
                break;
            }
        }
        if (found == NULL) {
            PROC_UNLOCK(p);
            sx_sunlock(&allproc_lock);
            return (1);
        }

        PROC_UNLOCK(p);
    }
    
    sx_xunlock(&allproc_lock);
    return (0);
}

// function that is called when the module is loaded and unloaded.
static int
load(struct module *module, int cmd, void *arg) {

    int ret = 0;

    switch (cmd) {
    case MOD_LOAD: { // case opening bracket so that there are no issues with vardecls.

        ret = allproc_in_pidhashtbl();

        break;

    } // closing bracket for the case opening bracket.

    default:
        break;
    }

    return (ret);
}

/* The second argument of DECLARE_MODULE. */
static moduledata_t kld_detect_listhash_consistency_mod = {
    "kld_detect_listhash_consistency",       /* module name */
    load,                                    /* event handler */
    NULL                                     /* extra data */
};

DECLARE_MODULE(kld_detect_listhash_consistency, kld_detect_listhash_consistency_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
