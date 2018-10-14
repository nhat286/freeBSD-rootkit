#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/pcpu.h>
#include <sys/syscall.h>
#include <sys/sysent.h>

// the instruction bytes that are common to all syscall function prologues.
static char common_function_prologue[] = {

    0x55,               // push   ebp
    0x89, 0xe5          // mov    ebp,esp

    // the instructions below are not necessarily the same
    // for all syscall function prologues.
    //
    // 0x57,               // push   edi
    // 0x56,               // push   esi
    // 0x8b, 0x7d, 0x0c,   // mov    edi,DWORD PTR [ebp+0xc]
    // 0x8b, 0x75, 0x08    // mov    esi,DWORD PTR [ebp+0x8]
};

// instruction bytes that redirect execution.
static char redirect_instructions[] = {

    // jmp
    0xeb,
    0xe9,
    0xea,

    // call
    0xe8,
    0x9a,

    // call or jmp
    0xff,

    // ret
    0xc3,
    0xcb,
    0xc2,
    0xca
};

static int
isRedirect(char instr) {
    for (unsigned int i = 0; i < sizeof(redirect_instructions)/sizeof(char); i++) {
        if (instr == redirect_instructions[i]) {
            return (1);
        }
    }
    return (0);
}

// function that is called when the module is loaded and unloaded.
static int
load(struct module *module, int cmd, void *arg) {

    (void) common_function_prologue;

    switch (cmd) {
    case MOD_LOAD: {

        for (unsigned int i = 0; i < SYS_MAXSYSCALL; i++) {
            char *sy_call = (char *)sysent[i].sy_call;

            for (unsigned int j = 0; j < sizeof(common_function_prologue)/sizeof(char); j++) {
                if (sy_call[j] != common_function_prologue[j]) {
                    return (1);
                }
            }

            // since the 0th instr is always "push ebp" (instr byte: 0x55)
            // and the 1st instr is always "mov ebp, esp" (instr byte: 0x89 0xe5)
            // for all of the syscall function prologues,
            // it is only possible for us to check the 0th, 1st, and 3rd bytes
            // to see if they are redirect instructions. the rest of the
            // bytes cannot be easily checked reliably.
            if (isRedirect(sy_call[0]) ||
                    isRedirect(sy_call[1]) ||
                    isRedirect(sy_call[3])) {
                return (1);
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
