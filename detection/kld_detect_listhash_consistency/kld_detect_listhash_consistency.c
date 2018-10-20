#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/pcpu.h>
#include <sys/mutex.h>
#include <sys/lock.h>
#include <sys/sx.h>
#include <sys/runq.h>
#include <sys/rwlock.h>

#define TRUE 1
#define FALSE 0

// returns TRUE if each proc in the allproc list is in the pidhashtbl.
// returns FALSE otherwise.
static int
allproc_in_pidhashtbl() {

    sx_xlock(&allproc_lock);
    struct proc *p = NULL;
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
        int isFound = FALSE;
        struct proc *found = NULL;
        LIST_FOREACH(found, PIDHASH(p->p_pid), p_hash) {

            if (found != NULL) {
                // if found == p (they are the same process),
                // then this if check will prevent us from double locking the process.
                if (!(PROC_LOCKED(found))) {
                    PROC_LOCK(found);
                }
                // XXX
                // it might be possible that rootkit processes may hide themselves
                // from being probed by setting their p_state to PRS_NEW.
                if (found->p_state == PRS_NEW) {
                    PROC_UNLOCK(found);
                    continue;
                }
                if (found->p_pid == p->p_pid) {
                    isFound = TRUE;
                    // XXX the currently held lock of the process *must* be
                    // released after breaking out of this foreach loop.
                    break;
                }
                // if these two processes have different mutexes,
                // it means that they are different processes.
                // if they are different processes, then it is
                // safe to release the mutex of found (again,
                // found proc is the process we are iterating through
                // in the allproc list).
                if (&(p->p_mtx) != &(found->p_mtx)) {
                    PROC_UNLOCK(found);
                // else somehow the mutexes of the two processes are the
                // same but their pids are different (because if their pids
                // were the same, then we would have broken out of the foreach
                // loop with the break statement in the if statement above).
                // XXX the currently held lock of the process *must* be
                // released after breaking out of this foreach loop.
                } else {
                    break;
                }
            }
        }

        if (isFound == FALSE) {
            PROC_UNLOCK(p);
            sx_sunlock(&allproc_lock);
            return (FALSE);
        }

        PROC_UNLOCK(p);
    }

    sx_xunlock(&allproc_lock);
    return (TRUE);
}

// returns TRUE if each proc in the pidhashtbl is in the allproc list.
// returns FALSE otherwise.
static int
pidhashtbl_in_allproc() {

    sx_xlock(&allproc_lock);
    for (pid_t i = 0; i <= pid_max; i++) {

        struct proc *p = NULL;
        LIST_FOREACH(p, PIDHASH(i), p_hash) {
            if (p != NULL) {
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

                if (p->p_pid == i) {

                    int isFound = FALSE;
                    struct proc *found = NULL;
                    FOREACH_PROC_IN_SYSTEM(found) {
                        // if found == p (they are the same process),
                        // then this if check will prevent us from double locking the process.
                        if (!(PROC_LOCKED(found))) {
                            PROC_LOCK(found);
                        }
                        // XXX
                        // it might be possible that rootkit processes may hide themselves
                        // from being probed by setting their p_state to PRS_NEW.
                        if (found->p_state == PRS_NEW) {
                            PROC_UNLOCK(found);
                            continue;
                        }
                        if (found->p_pid == i) {
                            isFound = TRUE;
                            // XXX the currently held lock of the process *must* be
                            // released after breaking out of this foreach loop.
                            break;
                        }
                        // if these two processes have different mutexes,
                        // it means that they are different processes.
                        // if they are different processes, then it is
                        // safe to release the mutex of found (again,
                        // found proc is the process we are iterating through
                        // in the allproc list).
                        if (&(p->p_mtx) != &(found->p_mtx)) {
                            PROC_UNLOCK(found);
                        // else somehow the mutexes of the two processes are the
                        // same but their pids are different (because if their pids
                        // were the same, then we would have broken out of the foreach
                        // loop with the break statement in the if statement above).
                        // XXX the currently held lock of the process *must* be
                        // released after breaking out of this foreach loop.
                        } else {
                            break;
                        }
                    }

                    if (isFound == FALSE) {
                        PROC_UNLOCK(p);
                        sx_xunlock(&allproc_lock);
                        return (FALSE);
                    }
                }

                PROC_UNLOCK(p);
            }
        }
    }

    sx_xunlock(&allproc_lock);
    return (TRUE);
}

// returns TRUE if nprocs is consistent with the number of procs in
// the allproc list, zombproc list, and pidhashtbl.
// the following should hold true:
//      nprocs == allproc + zombproc
//      nprocs == pidhashtbl entries + zombproc
// returns FALSE otherwise.
static int
nprocs_consistent() {

    sx_xlock(&allproc_lock);

    pid_t n_allprocs = 0;
    struct proc *p = NULL;
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
        n_allprocs++;
        PROC_UNLOCK(p);
    }

    pid_t n_zombprocs = 0;
    LIST_FOREACH(p, &zombproc, p_list) {
        n_zombprocs++;
    }

    if (n_allprocs + n_zombprocs != nprocs) {
        sx_xunlock(&allproc_lock);
        return (FALSE);
    }

    pid_t n_pidhashtbl = 0;
    for (pid_t i = 0; i <= pid_max; i++) {
        LIST_FOREACH(p, PIDHASH(i), p_hash) {

            if (p != NULL) {
                PROC_LOCK(p);

                if (p->p_pid == i) {
                    // if the process is currently being created,
                    // it may not have been completely initialized yet.
                    // XXX
                    // it might be possible that rootkit processes may hide themselves
                    // from being probed by setting their p_state to PRS_NEW.
                    if (p->p_state == PRS_NEW) {
                        PROC_UNLOCK(p);
                        continue;
                    }
                    n_pidhashtbl++;
                }

                PROC_UNLOCK(p);
            }
        }
    }

    if (n_pidhashtbl + n_zombprocs != nprocs) {
        sx_xunlock(&allproc_lock);
        return (FALSE);
    }

    sx_xunlock(&allproc_lock);
    return (TRUE);
}

// returns TRUE if the actual number of threads in each proc is consistent
// with the p_numthreads field in the proc.
// returns FALSE otherwise.
static int
nthreads_consistent() {

    sx_xlock(&allproc_lock);

    struct proc *p = NULL;
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

        int numthreads = 0;
        struct thread *td = NULL;
        FOREACH_THREAD_IN_PROC(p, td) {
            numthreads++;
        }

        if (numthreads != p->p_numthreads) {
            PROC_UNLOCK(p);
            sx_xunlock(&allproc_lock);
            return (FALSE);
        }

        PROC_UNLOCK(p);
    }

    sx_xunlock(&allproc_lock);
    return (TRUE);
}

// returns TRUE if all threads in each proc is in the tidhashtbl.
// returns FALSE otherwise.
static int
allthreads_in_tidhashtbl() {

    sx_xlock(&allproc_lock);
    rw_rlock(&tidhash_lock);

    struct proc *p = NULL;
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

        struct thread *td = NULL;
        FOREACH_THREAD_IN_PROC(p, td) {
            thread_lock(td);

            int isFound = FALSE;
            struct thread *found;
            LIST_FOREACH(found, TIDHASH(td->td_tid), td_hash) {
                if (found != NULL) {
                    if (td->td_lock != found->td_lock) {
                        thread_lock(found);
                    }

                    if (td->td_tid == found->td_tid) {
                        isFound = TRUE;
                        // XXX the currently held lock of the thread *must* be
                        // released after breaking out of the foreach loop.
                        break;
                    }

                    // if these two threads have different locks,
                    // it means that they are different threads.
                    // if they are different threads, then it is safe
                    // to release the lock of found (again, found thread
                    // is the thread we are iterating through in the threadlist
                    // of this proc).
                    if (td->td_lock != found->td_lock) {
                        thread_unlock(found);
                    // else somehow the locks of the two threads are the same
                    // but their tids are different (because if their tids
                    // were the same, then we would have broken out of the foreach
                    // loop with the break statement in the if statement above).
                    // XXX the currently held lock of the thread *must* be
                    // released after beakinf out of this foreach loop.
                    } else {
                        break;
                    }
                }
            }

            if (isFound == FALSE) {
                thread_unlock(td);
                PROC_UNLOCK(p);
                rw_runlock(&tidhash_lock);
                sx_sunlock(&allproc_lock);
                return (FALSE);
            }

            thread_unlock(td);
        }

        PROC_UNLOCK(p);
    }

    rw_runlock(&tidhash_lock);
    sx_xunlock(&allproc_lock);
    return (TRUE);
}

static void
print_bits(unsigned int num) {
    for (unsigned int mask = 1u << 31; mask != 0; mask >>= 1) {
        if (num & mask) {
            printf("1");
        } else {
            printf("0");
        }
    }
    printf("\n");
}


static int
threads_in_runq_consistent() {

#ifndef SMP

    // according to /sys/kern/sched_4bsd.c,
    // the td_lock of thread0 of proc0 (the scheduler proc) is the sched lock.
    // acquiring the sched lock should prevent proc0/the scheduler from
    // running and interfering with our operations.
    mtx_lock_spin(thread0.td_lock);
    critical_enter();

    // struct td_sched {
    //     fixpt_t		ts_pctcpu;	/* %cpu during p_swtime. */
    //     u_int		ts_estcpu;	/* Estimated cpu utilization. */
    //     int		ts_cpticks;	/* Ticks of cpu time. */
    //     int		ts_slptime;	/* Seconds !RUNNING. */
    //     int		ts_slice;	/* Remaining part of time slice. */
    //     int		ts_flags;
    //     struct runq	*ts_runq;	/* runq the thread is currently on */
    // #ifdef KTR
    // #define	TS_NAME_LEN (MAXCOMLEN + sizeof(" td ") + sizeof(__XSTRING(UINT_MAX)))
    //     char		ts_name[TS_NAME_LEN];
    // #endif /* KTR */
    // };

    thread_lock(curthread);
    char *ts = (char *)td_get_sched(curthread);
    struct runq *runq = (struct runq *) &(ts[24]);
    struct rqbits *rqb = &runq->rq_status;
    thread_unlock(curthread);

    if (rqb == NULL) {
        printf("rqb null\n");
    }
    // printf("***********************\n");
    // printf("***********************\n");
    // printf("***********************\n");
    // printf("struct td_sched *ts is: %p\n", ts);
    // printf("struct runq *runq address is: %p\n", runq);
    // printf("struct rqbits *rqb address is: %p\n", rqb);
    for (int rqnum = 0; rqnum < RQ_NQS; rqnum++) {

        // printf("RQB_WORD is: %d\n", RQB_WORD(rqnum));
        // printf("RQB_BIT is: ");
        // print_bits(RQB_BIT(rqnum));

        printf("rq number: %d\n", rqnum);

        // only check the threads in that runq if the runq is not empty.
        if (rqb->rqb_bits[RQB_WORD(rqnum)] & RQB_BIT(rqnum)) {

            struct rqhead *rqhead = &runq->rq_queues[rqnum];
            struct thread *td = NULL;
            // TAILQ_FOREACH(TYPE *var, TAILQ_HEAD *head, TAILQ_ENTRY NAME);
            TAILQ_FOREACH(td, rqhead, td_runq) {


                printf("thread: %p\n", td);

                if (td < (struct thread *)0xc0000000 || td >= (struct thread *)0xd0000000) {
                    printf("breaking out\n");
                    break;
                }

            }
            printf("bla \n");
        }
    }

    // release the scheduler lock.
    critical_exit();
    mtx_unlock_spin(thread0.td_lock);

#endif /* SMP */

    return (TRUE);
}

// function that is called when the module is loaded and unloaded.
static int
load(struct module *module, int cmd, void *arg) {

    int ret = 0;

    switch (cmd) {
    case MOD_LOAD: { // case opening bracket so that there are no issues with vardecls.
        int err;

        err = allproc_in_pidhashtbl();
        if (err == FALSE) {
            ret = 1;
            break;
        }

        err = pidhashtbl_in_allproc();
        if (err == FALSE) {
            ret = 1;
            break;
        }

        err = nprocs_consistent();
        if (err == FALSE) {
            ret = 1;
            break;
        }

        err = nthreads_consistent();
        if (err == FALSE) {
            ret = 1;
            break;
        }

        err = allthreads_in_tidhashtbl();
        if (err == FALSE) {
            ret = 1;
            break;
        }

        err = threads_in_runq_consistent();
        if (err == FALSE) {
            ret = 1;
            break;
        }

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
