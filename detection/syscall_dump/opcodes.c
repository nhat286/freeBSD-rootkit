#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>       /* thread, proc */
#include <sys/pcpu.h>       /* curthread */
#include <sys/sysent.h>     /* sysentvec, sysent, sy_call_t */
#include <sys/syscall.h>
#include <sys/mman.h>

/* The system call's arguments. */
struct sc_args {
    int fd;
    char *path;
    int flag;
    mode_t mode;
};

/* The function called at load/unload. */
static int
load(struct module *module, int cmd, void *arg) {

    switch (cmd) {

    case MOD_LOAD:

        printf("**^**");
        for (int i = 0; i < SYS_MAXSYSCALL; i++) {
            int j = 0;
            char *s = (char *) sysent[i].sy_call;
            for (; j == 0 || ((int) s) % PAGE_SIZE != 0; s++) {
                if (j == 30) break;
                printf("%x ", (unsigned int) (*s));
                j++;
            }
        }
        printf("**v**");

        break;

    default:
        break;
    }

    return (0);
}

/* The second argument of DECLARE_MODULE. */
static moduledata_t opcodes_mod = {
    "opcodes",       /* module name */
    load,           /* event handler */
    NULL            /* extra data */
};

DECLARE_MODULE(opcodes, opcodes_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
