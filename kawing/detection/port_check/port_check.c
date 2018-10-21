// make 
// sudo kldunload port_check.ko && sudo kldload ./port_check.ko && perl -e 'syscall(211);' && dmesg

/*-
 * Copyright (c) 2007 Joseph Kong.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the author nor the names of any co-contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/module.h>
#include <sys/sysent.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/sysproto.h>

#include <net/if.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/ip_var.h>
#include <netinet/tcp_var.h>

/*
Objectives:
-> check ipi_listhead and get "count"
-> get ipi_count and compare
-> get porthasebase and compare
-> get hashbase and compare 

Possible counter: UDP ports .... 
*/

/* System call to hide an open port. */
static int
port_checker(struct thread *td, void *syscall_args)
{
	//struct port_hiding_args *uap;
	//uap = (struct port_hiding_args *)syscall_args;

    // from tcp_var.h 
    // VNET_DECLARE(struct inpcbhead, tcb);
    // VNET_DECLARE(struct inpcbinfo, tcbinfo);

	struct inpcb *inpb;
    struct inpcbport *inpbport;
    int untrusted_count = 0;
    int hashbase_count = 0;
    int porthash_count = 0;
    // we iterate through ipi_listhead and get the supposed number of open ports
	INP_INFO_WLOCK(&tcbinfo);

    /*
      LIST_FOREACH(TYPE *var,   LIST_HEAD *head,  LIST_ENTRY NAME);
        - in this case ipi_listhead is the HEAD of the list
        - inpb is the var provided for referrence and TYPE 
        - the list to be iterated over (in this case inp_list)
     */

    // what confuses me is that in the struct inpcb theres ref. to inp_list (CK_LIST_ENTRY)
    //      as well as an inpcbinfo struct 
    // in inpcbinfo theres also ref. to inp_list  and the listhead itself 
    //      so is inpcbinfo first or last ?? 
	LIST_FOREACH(inpb, tcbinfo.ipi_listhead, inp_list) {
        untrusted_count++;
    }

    //INP_HASH_RLOCK(&tcbinfo);
    LIST_FOREACH(inpb, tcbinfo.ipi_hashbase, inp_hash) {
        hashbase_count++;
    }

    //ipi_porthashbase
    LIST_FOREACH(inpbport, tcbinfo.ipi_porthashbase, phd_hash) {
        porthash_count++;
    }

    //INP_HASH_RUNLOCK(&tcbinfo);
	INP_INFO_WUNLOCK(&tcbinfo);

    //wtf is a hashmask
    printf("HASHMASK: %lu\n", tcbinfo.ipi_hashmask);

    // print out this count
    printf("Untrusted inp_list count: %d\n", untrusted_count);

    //orint out gencount
    printf("Generation count: %llu\n", tcbinfo.ipi_gencnt);

    // now get ipi_count
    printf("ipi_count var says: %d\n", tcbinfo.ipi_count);

    // now get hashbase
    printf("hashbase_count says: %d\n", hashbase_count);

    // now get porthashbase
    printf("porthashbase_count says: %d\n", porthash_count);


    // ALL THESE lengths / size should line up 
	return(0);
}

/* The sysent for the new system call. */
static struct sysent port_checker_sysent = {
	0,			    /* number of arguments */
                    // our syscall doesn't take in any args 
	port_checker		/* implementing function */
};

/* The offset in sysent[] where the system call is to be allocated. */
static int offset = NO_SYSCALL;

/* The function called at load/unload. */
static int
load(struct module *module, int cmd, void *arg)
{
	int error = 0;

	switch (cmd) {
	case MOD_LOAD:
		uprintf("Port count checker loaded at offset [%d].\n", offset);
		break;

	case MOD_UNLOAD:
		uprintf("Port count checker unloaded from offset [%d].\n", offset);
		break;

	default:
		error = EOPNOTSUPP;
		break;
	}

	return(error);
}

SYSCALL_MODULE(port_checker, &offset, &port_checker_sysent, load, NULL);
