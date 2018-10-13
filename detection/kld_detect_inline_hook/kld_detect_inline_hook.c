#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/pcpu.h>
#include <sys/syscall.h>
#include <sys/sysent.h>

static char function_prologue[] = {
    0x55,               // push   ebp
    0x89, 0xe5,         // mov    ebp,esp
    0x57,               // push   edi
    0x56,               // push   esi
    0x8b, 0x7d, 0x0c,   // mov    edi,DWORD PTR [ebp+0xc]
    0x8b, 0x75, 0x08,   // mov    esi,DWORD PTR [ebp+0x8]
};

// function that is called when the module is loaded and unloaded.
static int
load(struct module *module, int cmd, void *arg) {

    switch (cmd) {
    case MOD_LOAD: {

        for (unsigned int i = 0; i < SYS_MAXSYSCALL; i++) {
            char *sy_call = (char *)sysent[i].sy_call;

            for (unsigned int j = 0; j < sizeof(function_prologue); j++) {
                if (sy_call[j] != function_prologue[j]) {
                    return (1);
                }
            }
        }

        break;
    }

    default:
        break;
    }

    return (0);
}

/* The second argument of DECLARE_MODULE. */
static moduledata_t kld_detect_inline_hook_mod = {
    "kld_detect_inline_hook",       /* module name */
    load,                           /* event handler */
    NULL                            /* extra data */
};

DECLARE_MODULE(kld_detect_inline_hook, kld_detect_inline_hook_mod, SI_SUB_DRIVERS, SI_ORDER_MIDDLE);
