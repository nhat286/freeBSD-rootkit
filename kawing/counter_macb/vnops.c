     1	/*-
     2	 * Copyright (c) 1982, 1986, 1989, 1993, 1995
     3	 *	The Regents of the University of California.  All rights reserved.
     4	 * (c) UNIX System Laboratories, Inc.
     5	 * All or some portions of this file are derived from material licensed
     6	 * to the University of California by American Telephone and Telegraph
     7	 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
     8	 * the permission of UNIX System Laboratories, Inc.
     9	 *
    10	 * Redistribution and use in source and binary forms, with or without
    11	 * modification, are permitted provided that the following conditions
    12	 * are met:
    13	 * 1. Redistributions of source code must retain the above copyright
    14	 *    notice, this list of conditions and the following disclaimer.
    15	 * 2. Redistributions in binary form must reproduce the above copyright
    16	 *    notice, this list of conditions and the following disclaimer in the
    17	 *    documentation and/or other materials provided with the distribution.
    18	 * 4. Neither the name of the University nor the names of its contributors
    19	 *    may be used to endorse or promote products derived from this software
    20	 *    without specific prior written permission.
    21	 *
    22	 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
    23	 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
    24	 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
    25	 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
    26	 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
    27	 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
    28	 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
    29	 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
    30	 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
    31	 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
    32	 * SUCH DAMAGE.
    33	 *
    34	 *	@(#)ufs_vnops.c	8.27 (Berkeley) 5/27/95
    35	 */
    36	
    37	#include <sys/cdefs.h>
    38	__FBSDID("$FreeBSD: releng/11.2/sys/ufs/ufs/ufs_vnops.c 332749 2018-04-19 02:47:21Z pfg $");
    39	
    40	#include "opt_quota.h"
    41	#include "opt_suiddir.h"
    42	#include "opt_ufs.h"
    43	#include "opt_ffs.h"
    44	
    45	#include <sys/param.h>
    46	#include <sys/systm.h>
    47	#include <sys/malloc.h>
    48	#include <sys/namei.h>
    49	#include <sys/kernel.h>
    50	#include <sys/fcntl.h>
    51	#include <sys/filio.h>
    52	#include <sys/stat.h>
    53	#include <sys/bio.h>
    54	#include <sys/buf.h>
    55	#include <sys/mount.h>
    56	#include <sys/priv.h>
    57	#include <sys/refcount.h>
    58	#include <sys/unistd.h>
    59	#include <sys/vnode.h>
    60	#include <sys/dirent.h>
    61	#include <sys/lockf.h>
    62	#include <sys/conf.h>
    63	#include <sys/acl.h>
    64	
    65	#include <security/mac/mac_framework.h>
    66	
    67	#include <sys/file.h>		/* XXX */
    68	
    69	#include <vm/vm.h>
    70	#include <vm/vm_extern.h>
    71	
    72	#include <ufs/ufs/acl.h>
    73	#include <ufs/ufs/extattr.h>
    74	#include <ufs/ufs/quota.h>
    75	#include <ufs/ufs/inode.h>
    76	#include <ufs/ufs/dir.h>
    77	#include <ufs/ufs/ufsmount.h>
    78	#include <ufs/ufs/ufs_extern.h>
    79	#ifdef UFS_DIRHASH
    80	#include <ufs/ufs/dirhash.h>
    81	#endif
    82	#ifdef UFS_GJOURNAL
    83	#include <ufs/ufs/gjournal.h>
    84	FEATURE(ufs_gjournal, "Journaling support through GEOM for UFS");
    85	#endif
    86	
    87	#ifdef QUOTA
    88	FEATURE(ufs_quota, "UFS disk quotas support");
    89	FEATURE(ufs_quota64, "64bit UFS disk quotas support");
    90	#endif
    91	
    92	#ifdef SUIDDIR
    93	FEATURE(suiddir,
    94	    "Give all new files in directory the same ownership as the directory");
    95	#endif
    96	
    97	
    98	#include <ufs/ffs/ffs_extern.h>
    99	
   100	static vop_accessx_t	ufs_accessx;
   101	static int ufs_chmod(struct vnode *, int, struct ucred *, struct thread *);
   102	static int ufs_chown(struct vnode *, uid_t, gid_t, struct ucred *, struct thread *);
   103	static vop_close_t	ufs_close;
   104	static vop_create_t	ufs_create;
   105	static vop_getattr_t	ufs_getattr;
   106	static vop_ioctl_t	ufs_ioctl;
   107	static vop_link_t	ufs_link;
   108	static int ufs_makeinode(int mode, struct vnode *, struct vnode **, struct componentname *, const char *);
   109	static vop_markatime_t	ufs_markatime;
   110	static vop_mkdir_t	ufs_mkdir;
   111	static vop_mknod_t	ufs_mknod;
   112	static vop_open_t	ufs_open;
   113	static vop_pathconf_t	ufs_pathconf;
   114	static vop_print_t	ufs_print;
   115	static vop_readlink_t	ufs_readlink;
   116	static vop_remove_t	ufs_remove;
   117	static vop_rename_t	ufs_rename;
   118	static vop_rmdir_t	ufs_rmdir;
   119	static vop_setattr_t	ufs_setattr;
   120	static vop_strategy_t	ufs_strategy;
   121	static vop_symlink_t	ufs_symlink;
   122	static vop_whiteout_t	ufs_whiteout;
   123	static vop_close_t	ufsfifo_close;
   124	static vop_kqfilter_t	ufsfifo_kqfilter;
   125	
   126	SYSCTL_NODE(_vfs, OID_AUTO, ufs, CTLFLAG_RD, 0, "UFS filesystem");
   127	
   128	/*
   129	 * A virgin directory (no blushing please).
   130	 */
   131	static struct dirtemplate mastertemplate = {
   132		0, 12, DT_DIR, 1, ".",
   133		0, DIRBLKSIZ - 12, DT_DIR, 2, ".."
   134	};
   135	static struct odirtemplate omastertemplate = {
   136		0, 12, 1, ".",
   137		0, DIRBLKSIZ - 12, 2, ".."
   138	};
   139	
   140	static void
   141	ufs_itimes_locked(struct vnode *vp)
   142	{
   143		struct inode *ip;
   144		struct timespec ts;
   145	
   146		ASSERT_VI_LOCKED(vp, __func__);
   147	
   148		ip = VTOI(vp);
   149		if (UFS_RDONLY(ip))
   150			goto out;
   151		if ((ip->i_flag & (IN_ACCESS | IN_CHANGE | IN_UPDATE)) == 0)
   152			return;
   153	
   154		if ((vp->v_type == VBLK || vp->v_type == VCHR) && !DOINGSOFTDEP(vp))
   155			ip->i_flag |= IN_LAZYMOD;
   156		else if (((vp->v_mount->mnt_kern_flag &
   157			    (MNTK_SUSPENDED | MNTK_SUSPEND)) == 0) ||
   158			    (ip->i_flag & (IN_CHANGE | IN_UPDATE)))
   159			ip->i_flag |= IN_MODIFIED;
   160		else if (ip->i_flag & IN_ACCESS)
   161			ip->i_flag |= IN_LAZYACCESS;
   162		vfs_timestamp(&ts);
   163		if (ip->i_flag & IN_ACCESS) {
   164			DIP_SET(ip, i_atime, ts.tv_sec);
   165			DIP_SET(ip, i_atimensec, ts.tv_nsec);
   166		}
   167		if (ip->i_flag & IN_UPDATE) {
   168			DIP_SET(ip, i_mtime, ts.tv_sec);
   169			DIP_SET(ip, i_mtimensec, ts.tv_nsec);
   170		}
   171		if (ip->i_flag & IN_CHANGE) {
   172			DIP_SET(ip, i_ctime, ts.tv_sec);
   173			DIP_SET(ip, i_ctimensec, ts.tv_nsec);
   174			DIP_SET(ip, i_modrev, DIP(ip, i_modrev) + 1);
   175		}
   176	
   177	 out:
   178		ip->i_flag &= ~(IN_ACCESS | IN_CHANGE | IN_UPDATE);
   179	}
   180	
   181	void
   182	ufs_itimes(struct vnode *vp)
   183	{
   184	
   185		VI_LOCK(vp);
   186		ufs_itimes_locked(vp);
   187		VI_UNLOCK(vp);
   188	}
   189	
   190	/*
   191	 * Create a regular file
   192	 */
   193	static int
   194	ufs_create(ap)
   195		struct vop_create_args /* {
   196			struct vnode *a_dvp;
   197			struct vnode **a_vpp;
   198			struct componentname *a_cnp;
   199			struct vattr *a_vap;
   200		} */ *ap;
   201	{
   202		int error;
   203	
   204		error =
   205		    ufs_makeinode(MAKEIMODE(ap->a_vap->va_type, ap->a_vap->va_mode),
   206		    ap->a_dvp, ap->a_vpp, ap->a_cnp, "ufs_create");
   207		if (error != 0)
   208			return (error);
   209		if ((ap->a_cnp->cn_flags & MAKEENTRY) != 0)
   210			cache_enter(ap->a_dvp, *ap->a_vpp, ap->a_cnp);
   211		return (0);
   212	}
   213	
   214	/*
   215	 * Mknod vnode call
   216	 */
   217	/* ARGSUSED */
   218	static int
   219	ufs_mknod(ap)
   220		struct vop_mknod_args /* {
   221			struct vnode *a_dvp;
   222			struct vnode **a_vpp;
   223			struct componentname *a_cnp;
   224			struct vattr *a_vap;
   225		} */ *ap;
   226	{
   227		struct vattr *vap = ap->a_vap;
   228		struct vnode **vpp = ap->a_vpp;
   229		struct inode *ip;
   230		ino_t ino;
   231		int error;
   232	
   233		error = ufs_makeinode(MAKEIMODE(vap->va_type, vap->va_mode),
   234		    ap->a_dvp, vpp, ap->a_cnp, "ufs_mknod");
   235		if (error)
   236			return (error);
   237		ip = VTOI(*vpp);
   238		ip->i_flag |= IN_ACCESS | IN_CHANGE | IN_UPDATE;
   239		if (vap->va_rdev != VNOVAL) {
   240			/*
   241			 * Want to be able to use this to make badblock
   242			 * inodes, so don't truncate the dev number.
   243			 */
   244			DIP_SET(ip, i_rdev, vap->va_rdev);
   245		}
   246		/*
   247		 * Remove inode, then reload it through VFS_VGET so it is
   248		 * checked to see if it is an alias of an existing entry in
   249		 * the inode cache.  XXX I don't believe this is necessary now.
   250		 */
   251		(*vpp)->v_type = VNON;
   252		ino = ip->i_number;	/* Save this before vgone() invalidates ip. */
   253		vgone(*vpp);
   254		vput(*vpp);
   255		error = VFS_VGET(ap->a_dvp->v_mount, ino, LK_EXCLUSIVE, vpp);
   256		if (error) {
   257			*vpp = NULL;
   258			return (error);
   259		}
   260		return (0);
   261	}
   262	
   263	/*
   264	 * Open called.
   265	 */
   266	/* ARGSUSED */
   267	static int
   268	ufs_open(struct vop_open_args *ap)
   269	{
   270		struct vnode *vp = ap->a_vp;
   271		struct inode *ip;
   272	
   273		if (vp->v_type == VCHR || vp->v_type == VBLK)
   274			return (EOPNOTSUPP);
   275	
   276		ip = VTOI(vp);
   277		/*
   278		 * Files marked append-only must be opened for appending.
   279		 */
   280		if ((ip->i_flags & APPEND) &&
   281		    (ap->a_mode & (FWRITE | O_APPEND)) == FWRITE)
   282			return (EPERM);
   283		vnode_create_vobject(vp, DIP(ip, i_size), ap->a_td);
   284		return (0);
   285	}
   286	
   287	/*
   288	 * Close called.
   289	 *
   290	 * Update the times on the inode.
   291	 */
   292	/* ARGSUSED */
   293	static int
   294	ufs_close(ap)
   295		struct vop_close_args /* {
   296			struct vnode *a_vp;
   297			int  a_fflag;
   298			struct ucred *a_cred;
   299			struct thread *a_td;
   300		} */ *ap;
   301	{
   302		struct vnode *vp = ap->a_vp;
   303		int usecount;
   304	
   305		VI_LOCK(vp);
   306		usecount = vp->v_usecount;
   307		if (usecount > 1)
   308			ufs_itimes_locked(vp);
   309		VI_UNLOCK(vp);
   310		return (0);
   311	}
   312	
   313	static int
   314	ufs_accessx(ap)
   315		struct vop_accessx_args /* {
   316			struct vnode *a_vp;
   317			accmode_t a_accmode;
   318			struct ucred *a_cred;
   319			struct thread *a_td;
   320		} */ *ap;
   321	{
   322		struct vnode *vp = ap->a_vp;
   323		struct inode *ip = VTOI(vp);
   324		accmode_t accmode = ap->a_accmode;
   325		int error;
   326	#ifdef QUOTA
   327		int relocked;
   328	#endif
   329	#ifdef UFS_ACL
   330		struct acl *acl;
   331		acl_type_t type;
   332	#endif
   333	
   334		/*
   335		 * Disallow write attempts on read-only filesystems;
   336		 * unless the file is a socket, fifo, or a block or
   337		 * character device resident on the filesystem.
   338		 */
   339		if (accmode & VMODIFY_PERMS) {
   340			switch (vp->v_type) {
   341			case VDIR:
   342			case VLNK:
   343			case VREG:
   344				if (vp->v_mount->mnt_flag & MNT_RDONLY)
   345					return (EROFS);
   346	#ifdef QUOTA
   347				/*
   348				 * Inode is accounted in the quotas only if struct
   349				 * dquot is attached to it. VOP_ACCESS() is called
   350				 * from vn_open_cred() and provides a convenient
   351				 * point to call getinoquota().
   352				 */
   353				if (VOP_ISLOCKED(vp) != LK_EXCLUSIVE) {
   354	
   355					/*
   356					 * Upgrade vnode lock, since getinoquota()
   357					 * requires exclusive lock to modify inode.
   358					 */
   359					relocked = 1;
   360					vhold(vp);
   361					vn_lock(vp, LK_UPGRADE | LK_RETRY);
   362					VI_LOCK(vp);
   363					if (vp->v_iflag & VI_DOOMED) {
   364						vdropl(vp);
   365						error = ENOENT;
   366						goto relock;
   367					}
   368					vdropl(vp);
   369				} else
   370					relocked = 0;
   371				error = getinoquota(ip);
   372	relock:
   373				if (relocked)
   374					vn_lock(vp, LK_DOWNGRADE | LK_RETRY);
   375				if (error != 0)
   376					return (error);
   377	#endif
   378				break;
   379			default:
   380				break;
   381			}
   382		}
   383	
   384		/*
   385		 * If immutable bit set, nobody gets to write it.  "& ~VADMIN_PERMS"
   386		 * permits the owner of the file to remove the IMMUTABLE flag.
   387		 */
   388		if ((accmode & (VMODIFY_PERMS & ~VADMIN_PERMS)) &&
   389		    (ip->i_flags & (IMMUTABLE | SF_SNAPSHOT)))
   390			return (EPERM);
   391	
   392	#ifdef UFS_ACL
   393		if ((vp->v_mount->mnt_flag & (MNT_ACLS | MNT_NFS4ACLS)) != 0) {
   394			if (vp->v_mount->mnt_flag & MNT_NFS4ACLS)
   395				type = ACL_TYPE_NFS4;
   396			else
   397				type = ACL_TYPE_ACCESS;
   398	
   399			acl = acl_alloc(M_WAITOK);
   400			if (type == ACL_TYPE_NFS4)
   401				error = ufs_getacl_nfs4_internal(vp, acl, ap->a_td);
   402			else
   403				error = VOP_GETACL(vp, type, acl, ap->a_cred, ap->a_td);
   404			switch (error) {
   405			case 0:
   406				if (type == ACL_TYPE_NFS4) {
   407					error = vaccess_acl_nfs4(vp->v_type, ip->i_uid,
   408					    ip->i_gid, acl, accmode, ap->a_cred, NULL);
   409				} else {
   410					error = vfs_unixify_accmode(&accmode);
   411					if (error == 0)
   412						error = vaccess_acl_posix1e(vp->v_type, ip->i_uid,
   413						    ip->i_gid, acl, accmode, ap->a_cred, NULL);
   414				}
   415				break;
   416			default:
   417				if (error != EOPNOTSUPP)
   418					printf(
   419	"ufs_accessx(): Error retrieving ACL on object (%d).\n",
   420					    error);
   421				/*
   422				 * XXX: Fall back until debugged.  Should
   423				 * eventually possibly log an error, and return
   424				 * EPERM for safety.
   425				 */
   426				error = vfs_unixify_accmode(&accmode);
   427				if (error == 0)
   428					error = vaccess(vp->v_type, ip->i_mode, ip->i_uid,
   429					    ip->i_gid, accmode, ap->a_cred, NULL);
   430			}
   431			acl_free(acl);
   432	
   433			return (error);
   434		}
   435	#endif /* !UFS_ACL */
   436		error = vfs_unixify_accmode(&accmode);
   437		if (error == 0)
   438			error = vaccess(vp->v_type, ip->i_mode, ip->i_uid, ip->i_gid,
   439			    accmode, ap->a_cred, NULL);
   440		return (error);
   441	}
   442	
   443	/* ARGSUSED */
   444	static int
   445	ufs_getattr(ap)
   446		struct vop_getattr_args /* {
   447			struct vnode *a_vp;
   448			struct vattr *a_vap;
   449			struct ucred *a_cred;
   450		} */ *ap;
   451	{
   452		struct vnode *vp = ap->a_vp;
   453		struct inode *ip = VTOI(vp);
   454		struct vattr *vap = ap->a_vap;
   455	
   456		VI_LOCK(vp);
   457		ufs_itimes_locked(vp);
   458		if (I_IS_UFS1(ip)) {
   459			vap->va_atime.tv_sec = ip->i_din1->di_atime;
   460			vap->va_atime.tv_nsec = ip->i_din1->di_atimensec;
   461		} else {
   462			vap->va_atime.tv_sec = ip->i_din2->di_atime;
   463			vap->va_atime.tv_nsec = ip->i_din2->di_atimensec;
   464		}
   465		VI_UNLOCK(vp);
   466		/*
   467		 * Copy from inode table
   468		 */
   469		vap->va_fsid = dev2udev(ITOUMP(ip)->um_dev);
   470		vap->va_fileid = ip->i_number;
   471		vap->va_mode = ip->i_mode & ~IFMT;
   472		vap->va_nlink = ip->i_effnlink;
   473		vap->va_uid = ip->i_uid;
   474		vap->va_gid = ip->i_gid;
   475		if (I_IS_UFS1(ip)) {
   476			vap->va_rdev = ip->i_din1->di_rdev;
   477			vap->va_size = ip->i_din1->di_size;
   478			vap->va_mtime.tv_sec = ip->i_din1->di_mtime;
   479			vap->va_mtime.tv_nsec = ip->i_din1->di_mtimensec;
   480			vap->va_ctime.tv_sec = ip->i_din1->di_ctime;
   481			vap->va_ctime.tv_nsec = ip->i_din1->di_ctimensec;
   482			vap->va_bytes = dbtob((u_quad_t)ip->i_din1->di_blocks);
   483			vap->va_filerev = ip->i_din1->di_modrev;
   484		} else {
   485			vap->va_rdev = ip->i_din2->di_rdev;
   486			vap->va_size = ip->i_din2->di_size;
   487			vap->va_mtime.tv_sec = ip->i_din2->di_mtime;
   488			vap->va_mtime.tv_nsec = ip->i_din2->di_mtimensec;
   489			vap->va_ctime.tv_sec = ip->i_din2->di_ctime;
   490			vap->va_ctime.tv_nsec = ip->i_din2->di_ctimensec;
   491			vap->va_birthtime.tv_sec = ip->i_din2->di_birthtime;
   492			vap->va_birthtime.tv_nsec = ip->i_din2->di_birthnsec;
   493			vap->va_bytes = dbtob((u_quad_t)ip->i_din2->di_blocks);
   494			vap->va_filerev = ip->i_din2->di_modrev;
   495		}
   496		vap->va_flags = ip->i_flags;
   497		vap->va_gen = ip->i_gen;
   498		vap->va_blocksize = vp->v_mount->mnt_stat.f_iosize;
   499		vap->va_type = IFTOVT(ip->i_mode);
   500		return (0);
   501	}
   502	
   503	/*
   504	 * Set attribute vnode op. called from several syscalls
   505	 */
   506	static int
   507	ufs_setattr(ap)
   508		struct vop_setattr_args /* {
   509			struct vnode *a_vp;
   510			struct vattr *a_vap;
   511			struct ucred *a_cred;
   512		} */ *ap;
   513	{
   514		struct vattr *vap = ap->a_vap;
   515		struct vnode *vp = ap->a_vp;
   516		struct inode *ip = VTOI(vp);
   517		struct ucred *cred = ap->a_cred;
   518		struct thread *td = curthread;
   519		int error;
   520	
   521		/*
   522		 * Check for unsettable attributes.
   523		 */
   524		if ((vap->va_type != VNON) || (vap->va_nlink != VNOVAL) ||
   525		    (vap->va_fsid != VNOVAL) || (vap->va_fileid != VNOVAL) ||
   526		    (vap->va_blocksize != VNOVAL) || (vap->va_rdev != VNOVAL) ||
   527		    ((int)vap->va_bytes != VNOVAL) || (vap->va_gen != VNOVAL)) {
   528			return (EINVAL);
   529		}
   530		if (vap->va_flags != VNOVAL) {
   531			if ((vap->va_flags & ~(SF_APPEND | SF_ARCHIVED | SF_IMMUTABLE |
   532			    SF_NOUNLINK | SF_SNAPSHOT | UF_APPEND | UF_ARCHIVE |
   533			    UF_HIDDEN | UF_IMMUTABLE | UF_NODUMP | UF_NOUNLINK |
   534			    UF_OFFLINE | UF_OPAQUE | UF_READONLY | UF_REPARSE |
   535			    UF_SPARSE | UF_SYSTEM)) != 0)
   536				return (EOPNOTSUPP);
   537			if (vp->v_mount->mnt_flag & MNT_RDONLY)
   538				return (EROFS);
   539			/*
   540			 * Callers may only modify the file flags on objects they
   541			 * have VADMIN rights for.
   542			 */
   543			if ((error = VOP_ACCESS(vp, VADMIN, cred, td)))
   544				return (error);
   545			/*
   546			 * Unprivileged processes are not permitted to unset system
   547			 * flags, or modify flags if any system flags are set.
   548			 * Privileged non-jail processes may not modify system flags
   549			 * if securelevel > 0 and any existing system flags are set.
   550			 * Privileged jail processes behave like privileged non-jail
   551			 * processes if the security.jail.chflags_allowed sysctl is
   552			 * is non-zero; otherwise, they behave like unprivileged
   553			 * processes.
   554			 */
   555			if (!priv_check_cred(cred, PRIV_VFS_SYSFLAGS, 0)) {
   556				if (ip->i_flags &
   557				    (SF_NOUNLINK | SF_IMMUTABLE | SF_APPEND)) {
   558					error = securelevel_gt(cred, 0);
   559					if (error)
   560						return (error);
   561				}
   562				/* The snapshot flag cannot be toggled. */
   563				if ((vap->va_flags ^ ip->i_flags) & SF_SNAPSHOT)
   564					return (EPERM);
   565			} else {
   566				if (ip->i_flags &
   567				    (SF_NOUNLINK | SF_IMMUTABLE | SF_APPEND) ||
   568				    ((vap->va_flags ^ ip->i_flags) & SF_SETTABLE))
   569					return (EPERM);
   570			}
   571			ip->i_flags = vap->va_flags;
   572			DIP_SET(ip, i_flags, vap->va_flags);
   573			ip->i_flag |= IN_CHANGE;
   574			error = UFS_UPDATE(vp, 0);
   575			if (ip->i_flags & (IMMUTABLE | APPEND))
   576				return (error);
   577		}
   578		/*
   579		 * If immutable or append, no one can change any of its attributes
   580		 * except the ones already handled (in some cases, file flags
   581		 * including the immutability flags themselves for the superuser).
   582		 */
   583		if (ip->i_flags & (IMMUTABLE | APPEND))
   584			return (EPERM);
   585		/*
   586		 * Go through the fields and update iff not VNOVAL.
   587		 */
   588		if (vap->va_uid != (uid_t)VNOVAL || vap->va_gid != (gid_t)VNOVAL) {
   589			if (vp->v_mount->mnt_flag & MNT_RDONLY)
   590				return (EROFS);
   591			if ((error = ufs_chown(vp, vap->va_uid, vap->va_gid, cred,
   592			    td)) != 0)
   593				return (error);
   594		}
   595		if (vap->va_size != VNOVAL) {
   596			/*
   597			 * XXX most of the following special cases should be in
   598			 * callers instead of in N filesystems.  The VDIR check
   599			 * mostly already is.
   600			 */
   601			switch (vp->v_type) {
   602			case VDIR:
   603				return (EISDIR);
   604			case VLNK:
   605			case VREG:
   606				/*
   607				 * Truncation should have an effect in these cases.
   608				 * Disallow it if the filesystem is read-only or
   609				 * the file is being snapshotted.
   610				 */
   611				if (vp->v_mount->mnt_flag & MNT_RDONLY)
   612					return (EROFS);
   613				if ((ip->i_flags & SF_SNAPSHOT) != 0)
   614					return (EPERM);
   615				break;
   616			default:
   617				/*
   618				 * According to POSIX, the result is unspecified
   619				 * for file types other than regular files,
   620				 * directories and shared memory objects.  We
   621				 * don't support shared memory objects in the file
   622				 * system, and have dubious support for truncating
   623				 * symlinks.  Just ignore the request in other cases.
   624				 */
   625				return (0);
   626			}
   627			if ((error = UFS_TRUNCATE(vp, vap->va_size, IO_NORMAL |
   628			    ((vap->va_vaflags & VA_SYNC) != 0 ? IO_SYNC : 0),
   629			    cred)) != 0)
   630				return (error);
   631		}
   632		if (vap->va_atime.tv_sec != VNOVAL ||
   633		    vap->va_mtime.tv_sec != VNOVAL ||
   634		    vap->va_birthtime.tv_sec != VNOVAL) {
   635			if (vp->v_mount->mnt_flag & MNT_RDONLY)
   636				return (EROFS);
   637			if ((ip->i_flags & SF_SNAPSHOT) != 0)
   638				return (EPERM);
   639			error = vn_utimes_perm(vp, vap, cred, td);
   640			if (error != 0)
   641				return (error);
   642			ip->i_flag |= IN_CHANGE | IN_MODIFIED;
   643			if (vap->va_atime.tv_sec != VNOVAL) {
   644				ip->i_flag &= ~IN_ACCESS;
   645				DIP_SET(ip, i_atime, vap->va_atime.tv_sec);
   646				DIP_SET(ip, i_atimensec, vap->va_atime.tv_nsec);
   647			}
   648			if (vap->va_mtime.tv_sec != VNOVAL) {
   649				ip->i_flag &= ~IN_UPDATE;
   650				DIP_SET(ip, i_mtime, vap->va_mtime.tv_sec);
   651				DIP_SET(ip, i_mtimensec, vap->va_mtime.tv_nsec);
   652			}
   653			if (vap->va_birthtime.tv_sec != VNOVAL && I_IS_UFS2(ip)) {
   654				ip->i_din2->di_birthtime = vap->va_birthtime.tv_sec;
   655				ip->i_din2->di_birthnsec = vap->va_birthtime.tv_nsec;
   656			}
   657			error = UFS_UPDATE(vp, 0);
   658			if (error)
   659				return (error);
   660		}
   661		error = 0;
   662		if (vap->va_mode != (mode_t)VNOVAL) {
   663			if (vp->v_mount->mnt_flag & MNT_RDONLY)
   664				return (EROFS);
   665			if ((ip->i_flags & SF_SNAPSHOT) != 0 && (vap->va_mode &
   666			   (S_IXUSR | S_IWUSR | S_IXGRP | S_IWGRP | S_IXOTH | S_IWOTH)))
   667				return (EPERM);
   668			error = ufs_chmod(vp, (int)vap->va_mode, cred, td);
   669		}
   670		return (error);
   671	}
   672	
   673	#ifdef UFS_ACL
   674	static int
   675	ufs_update_nfs4_acl_after_mode_change(struct vnode *vp, int mode,
   676	    int file_owner_id, struct ucred *cred, struct thread *td)
   677	{
   678		int error;
   679		struct acl *aclp;
   680	
   681		aclp = acl_alloc(M_WAITOK);
   682		error = ufs_getacl_nfs4_internal(vp, aclp, td);
   683		/*
   684		 * We don't have to handle EOPNOTSUPP here, as the filesystem claims
   685		 * it supports ACLs.
   686		 */
   687		if (error)
   688			goto out;
   689	
   690		acl_nfs4_sync_acl_from_mode(aclp, mode, file_owner_id);
   691		error = ufs_setacl_nfs4_internal(vp, aclp, td);
   692	
   693	out:
   694		acl_free(aclp);
   695		return (error);
   696	}
   697	#endif /* UFS_ACL */
   698	
   699	/*
   700	 * Mark this file's access time for update for vfs_mark_atime().  This
   701	 * is called from execve() and mmap().
   702	 */
   703	static int
   704	ufs_markatime(ap)
   705		struct vop_markatime_args /* {
   706			struct vnode *a_vp;
   707		} */ *ap;
   708	{
   709		struct vnode *vp = ap->a_vp;
   710		struct inode *ip = VTOI(vp);
   711	
   712		VI_LOCK(vp);
   713		ip->i_flag |= IN_ACCESS;
   714		VI_UNLOCK(vp);
   715		/*
   716		 * XXXKIB No UFS_UPDATE(ap->a_vp, 0) there.
   717		 */
   718		return (0);
   719	}
   720	
   721	/*
   722	 * Change the mode on a file.
   723	 * Inode must be locked before calling.
   724	 */
   725	static int
   726	ufs_chmod(vp, mode, cred, td)
   727		struct vnode *vp;
   728		int mode;
   729		struct ucred *cred;
   730		struct thread *td;
   731	{
   732		struct inode *ip = VTOI(vp);
   733		int error;
   734	
   735		/*
   736		 * To modify the permissions on a file, must possess VADMIN
   737		 * for that file.
   738		 */
   739		if ((error = VOP_ACCESSX(vp, VWRITE_ACL, cred, td)))
   740			return (error);
   741		/*
   742		 * Privileged processes may set the sticky bit on non-directories,
   743		 * as well as set the setgid bit on a file with a group that the
   744		 * process is not a member of.  Both of these are allowed in
   745		 * jail(8).
   746		 */
   747		if (vp->v_type != VDIR && (mode & S_ISTXT)) {
   748			if (priv_check_cred(cred, PRIV_VFS_STICKYFILE, 0))
   749				return (EFTYPE);
   750		}
   751		if (!groupmember(ip->i_gid, cred) && (mode & ISGID)) {
   752			error = priv_check_cred(cred, PRIV_VFS_SETGID, 0);
   753			if (error)
   754				return (error);
   755		}
   756	
   757		/*
   758		 * Deny setting setuid if we are not the file owner.
   759		 */
   760		if ((mode & ISUID) && ip->i_uid != cred->cr_uid) {
   761			error = priv_check_cred(cred, PRIV_VFS_ADMIN, 0);
   762			if (error)
   763				return (error);
   764		}
   765	
   766		ip->i_mode &= ~ALLPERMS;
   767		ip->i_mode |= (mode & ALLPERMS);
   768		DIP_SET(ip, i_mode, ip->i_mode);
   769		ip->i_flag |= IN_CHANGE;
   770	#ifdef UFS_ACL
   771		if ((vp->v_mount->mnt_flag & MNT_NFS4ACLS) != 0)
   772			error = ufs_update_nfs4_acl_after_mode_change(vp, mode, ip->i_uid, cred, td);
   773	#endif
   774		if (error == 0 && (ip->i_flag & IN_CHANGE) != 0)
   775			error = UFS_UPDATE(vp, 0);
   776	
   777		return (error);
   778	}
   779	
   780	/*
   781	 * Perform chown operation on inode ip;
   782	 * inode must be locked prior to call.
   783	 */
   784	static int
   785	ufs_chown(vp, uid, gid, cred, td)
   786		struct vnode *vp;
   787		uid_t uid;
   788		gid_t gid;
   789		struct ucred *cred;
   790		struct thread *td;
   791	{
   792		struct inode *ip = VTOI(vp);
   793		uid_t ouid;
   794		gid_t ogid;
   795		int error = 0;
   796	#ifdef QUOTA
   797		int i;
   798		ufs2_daddr_t change;
   799	#endif
   800	
   801		if (uid == (uid_t)VNOVAL)
   802			uid = ip->i_uid;
   803		if (gid == (gid_t)VNOVAL)
   804			gid = ip->i_gid;
   805		/*
   806		 * To modify the ownership of a file, must possess VADMIN for that
   807		 * file.
   808		 */
   809		if ((error = VOP_ACCESSX(vp, VWRITE_OWNER, cred, td)))
   810			return (error);
   811		/*
   812		 * To change the owner of a file, or change the group of a file to a
   813		 * group of which we are not a member, the caller must have
   814		 * privilege.
   815		 */
   816		if (((uid != ip->i_uid && uid != cred->cr_uid) || 
   817		    (gid != ip->i_gid && !groupmember(gid, cred))) &&
   818		    (error = priv_check_cred(cred, PRIV_VFS_CHOWN, 0)))
   819			return (error);
   820		ogid = ip->i_gid;
   821		ouid = ip->i_uid;
   822	#ifdef QUOTA
   823		if ((error = getinoquota(ip)) != 0)
   824			return (error);
   825		if (ouid == uid) {
   826			dqrele(vp, ip->i_dquot[USRQUOTA]);
   827			ip->i_dquot[USRQUOTA] = NODQUOT;
   828		}
   829		if (ogid == gid) {
   830			dqrele(vp, ip->i_dquot[GRPQUOTA]);
   831			ip->i_dquot[GRPQUOTA] = NODQUOT;
   832		}
   833		change = DIP(ip, i_blocks);
   834		(void) chkdq(ip, -change, cred, CHOWN);
   835		(void) chkiq(ip, -1, cred, CHOWN);
   836		for (i = 0; i < MAXQUOTAS; i++) {
   837			dqrele(vp, ip->i_dquot[i]);
   838			ip->i_dquot[i] = NODQUOT;
   839		}
   840	#endif
   841		ip->i_gid = gid;
   842		DIP_SET(ip, i_gid, gid);
   843		ip->i_uid = uid;
   844		DIP_SET(ip, i_uid, uid);
   845	#ifdef QUOTA
   846		if ((error = getinoquota(ip)) == 0) {
   847			if (ouid == uid) {
   848				dqrele(vp, ip->i_dquot[USRQUOTA]);
   849				ip->i_dquot[USRQUOTA] = NODQUOT;
   850			}
   851			if (ogid == gid) {
   852				dqrele(vp, ip->i_dquot[GRPQUOTA]);
   853				ip->i_dquot[GRPQUOTA] = NODQUOT;
   854			}
   855			if ((error = chkdq(ip, change, cred, CHOWN)) == 0) {
   856				if ((error = chkiq(ip, 1, cred, CHOWN)) == 0)
   857					goto good;
   858				else
   859					(void) chkdq(ip, -change, cred, CHOWN|FORCE);
   860			}
   861			for (i = 0; i < MAXQUOTAS; i++) {
   862				dqrele(vp, ip->i_dquot[i]);
   863				ip->i_dquot[i] = NODQUOT;
   864			}
   865		}
   866		ip->i_gid = ogid;
   867		DIP_SET(ip, i_gid, ogid);
   868		ip->i_uid = ouid;
   869		DIP_SET(ip, i_uid, ouid);
   870		if (getinoquota(ip) == 0) {
   871			if (ouid == uid) {
   872				dqrele(vp, ip->i_dquot[USRQUOTA]);
   873				ip->i_dquot[USRQUOTA] = NODQUOT;
   874			}
   875			if (ogid == gid) {
   876				dqrele(vp, ip->i_dquot[GRPQUOTA]);
   877				ip->i_dquot[GRPQUOTA] = NODQUOT;
   878			}
   879			(void) chkdq(ip, change, cred, FORCE|CHOWN);
   880			(void) chkiq(ip, 1, cred, FORCE|CHOWN);
   881			(void) getinoquota(ip);
   882		}
   883		return (error);
   884	good:
   885		if (getinoquota(ip))
   886			panic("ufs_chown: lost quota");
   887	#endif /* QUOTA */
   888		ip->i_flag |= IN_CHANGE;
   889		if ((ip->i_mode & (ISUID | ISGID)) && (ouid != uid || ogid != gid)) {
   890			if (priv_check_cred(cred, PRIV_VFS_RETAINSUGID, 0)) {
   891				ip->i_mode &= ~(ISUID | ISGID);
   892				DIP_SET(ip, i_mode, ip->i_mode);
   893			}
   894		}
   895		error = UFS_UPDATE(vp, 0);
   896		return (error);
   897	}
   898	
   899	static int
   900	ufs_remove(ap)
   901		struct vop_remove_args /* {
   902			struct vnode *a_dvp;
   903			struct vnode *a_vp;
   904			struct componentname *a_cnp;
   905		} */ *ap;
   906	{
   907		struct inode *ip;
   908		struct vnode *vp = ap->a_vp;
   909		struct vnode *dvp = ap->a_dvp;
   910		int error;
   911		struct thread *td;
   912	
   913		td = curthread;
   914		ip = VTOI(vp);
   915		if ((ip->i_flags & (NOUNLINK | IMMUTABLE | APPEND)) ||
   916		    (VTOI(dvp)->i_flags & APPEND)) {
   917			error = EPERM;
   918			goto out;
   919		}
   920	#ifdef UFS_GJOURNAL
   921		ufs_gjournal_orphan(vp);
   922	#endif
   923		error = ufs_dirremove(dvp, ip, ap->a_cnp->cn_flags, 0);
   924		if (ip->i_nlink <= 0)
   925			vp->v_vflag |= VV_NOSYNC;
   926		if ((ip->i_flags & SF_SNAPSHOT) != 0) {
   927			/*
   928			 * Avoid deadlock where another thread is trying to
   929			 * update the inodeblock for dvp and is waiting on
   930			 * snaplk.  Temporary unlock the vnode lock for the
   931			 * unlinked file and sync the directory.  This should
   932			 * allow vput() of the directory to not block later on
   933			 * while holding the snapshot vnode locked, assuming
   934			 * that the directory hasn't been unlinked too.
   935			 */
   936			VOP_UNLOCK(vp, 0);
   937			(void) VOP_FSYNC(dvp, MNT_WAIT, td);
   938			vn_lock(vp, LK_EXCLUSIVE | LK_RETRY);
   939		}
   940	out:
   941		return (error);
   942	}
   943	
   944	static void
   945	print_bad_link_count(const char *funcname, struct vnode *dvp)
   946	{
   947		struct inode *dip;
   948	
   949		dip = VTOI(dvp);
   950		uprintf("%s: Bad link count %d on parent inode %jd in file system %s\n",
   951		    funcname, dip->i_effnlink, (intmax_t)dip->i_number,
   952		    dvp->v_mount->mnt_stat.f_mntonname);
   953	}
   954	
   955	/*
   956	 * link vnode call
   957	 */
   958	static int
   959	ufs_link(ap)
   960		struct vop_link_args /* {
   961			struct vnode *a_tdvp;
   962			struct vnode *a_vp;
   963			struct componentname *a_cnp;
   964		} */ *ap;
   965	{
   966		struct vnode *vp = ap->a_vp;
   967		struct vnode *tdvp = ap->a_tdvp;
   968		struct componentname *cnp = ap->a_cnp;
   969		struct inode *ip;
   970		struct direct newdir;
   971		int error;
   972	
   973	#ifdef INVARIANTS
   974		if ((cnp->cn_flags & HASBUF) == 0)
   975			panic("ufs_link: no name");
   976	#endif
   977		if (VTOI(tdvp)->i_effnlink < 2) {
   978			print_bad_link_count("ufs_link", tdvp);
   979			error = EINVAL;
   980			goto out;
   981		}
   982		ip = VTOI(vp);
   983		if ((nlink_t)ip->i_nlink >= LINK_MAX) {
   984			error = EMLINK;
   985			goto out;
   986		}
   987		/*
   988		 * The file may have been removed after namei droped the original
   989		 * lock.
   990		 */
   991		if (ip->i_effnlink == 0) {
   992			error = ENOENT;
   993			goto out;
   994		}
   995		if (ip->i_flags & (IMMUTABLE | APPEND)) {
   996			error = EPERM;
   997			goto out;
   998		}
   999		ip->i_effnlink++;
  1000		ip->i_nlink++;
  1001		DIP_SET(ip, i_nlink, ip->i_nlink);
  1002		ip->i_flag |= IN_CHANGE;
  1003		if (DOINGSOFTDEP(vp))
  1004			softdep_setup_link(VTOI(tdvp), ip);
  1005		error = UFS_UPDATE(vp, !(DOINGSOFTDEP(vp) | DOINGASYNC(vp)));
  1006		if (!error) {
  1007			ufs_makedirentry(ip, cnp, &newdir);
  1008			error = ufs_direnter(tdvp, vp, &newdir, cnp, NULL, 0);
  1009		}
  1010	
  1011		if (error) {
  1012			ip->i_effnlink--;
  1013			ip->i_nlink--;
  1014			DIP_SET(ip, i_nlink, ip->i_nlink);
  1015			ip->i_flag |= IN_CHANGE;
  1016			if (DOINGSOFTDEP(vp))
  1017				softdep_revert_link(VTOI(tdvp), ip);
  1018		}
  1019	out:
  1020		return (error);
  1021	}
  1022	
  1023	/*
  1024	 * whiteout vnode call
  1025	 */
  1026	static int
  1027	ufs_whiteout(ap)
  1028		struct vop_whiteout_args /* {
  1029			struct vnode *a_dvp;
  1030			struct componentname *a_cnp;
  1031			int a_flags;
  1032		} */ *ap;
  1033	{
  1034		struct vnode *dvp = ap->a_dvp;
  1035		struct componentname *cnp = ap->a_cnp;
  1036		struct direct newdir;
  1037		int error = 0;
  1038	
  1039		switch (ap->a_flags) {
  1040		case LOOKUP:
  1041			/* 4.4 format directories support whiteout operations */
  1042			if (dvp->v_mount->mnt_maxsymlinklen > 0)
  1043				return (0);
  1044			return (EOPNOTSUPP);
  1045	
  1046		case CREATE:
  1047			/* create a new directory whiteout */
  1048	#ifdef INVARIANTS
  1049			if ((cnp->cn_flags & SAVENAME) == 0)
  1050				panic("ufs_whiteout: missing name");
  1051			if (dvp->v_mount->mnt_maxsymlinklen <= 0)
  1052				panic("ufs_whiteout: old format filesystem");
  1053	#endif
  1054	
  1055			newdir.d_ino = WINO;
  1056			newdir.d_namlen = cnp->cn_namelen;
  1057			bcopy(cnp->cn_nameptr, newdir.d_name, (unsigned)cnp->cn_namelen + 1);
  1058			newdir.d_type = DT_WHT;
  1059			error = ufs_direnter(dvp, NULL, &newdir, cnp, NULL, 0);
  1060			break;
  1061	
  1062		case DELETE:
  1063			/* remove an existing directory whiteout */
  1064	#ifdef INVARIANTS
  1065			if (dvp->v_mount->mnt_maxsymlinklen <= 0)
  1066				panic("ufs_whiteout: old format filesystem");
  1067	#endif
  1068	
  1069			cnp->cn_flags &= ~DOWHITEOUT;
  1070			error = ufs_dirremove(dvp, NULL, cnp->cn_flags, 0);
  1071			break;
  1072		default:
  1073			panic("ufs_whiteout: unknown op");
  1074		}
  1075		return (error);
  1076	}
  1077	
  1078	static volatile int rename_restarts;
  1079	SYSCTL_INT(_vfs_ufs, OID_AUTO, rename_restarts, CTLFLAG_RD,
  1080	    __DEVOLATILE(int *, &rename_restarts), 0,
  1081	    "Times rename had to restart due to lock contention");
  1082	
  1083	/*
  1084	 * Rename system call.
  1085	 * 	rename("foo", "bar");
  1086	 * is essentially
  1087	 *	unlink("bar");
  1088	 *	link("foo", "bar");
  1089	 *	unlink("foo");
  1090	 * but ``atomically''.  Can't do full commit without saving state in the
  1091	 * inode on disk which isn't feasible at this time.  Best we can do is
  1092	 * always guarantee the target exists.
  1093	 *
  1094	 * Basic algorithm is:
  1095	 *
  1096	 * 1) Bump link count on source while we're linking it to the
  1097	 *    target.  This also ensure the inode won't be deleted out
  1098	 *    from underneath us while we work (it may be truncated by
  1099	 *    a concurrent `trunc' or `open' for creation).
  1100	 * 2) Link source to destination.  If destination already exists,
  1101	 *    delete it first.
  1102	 * 3) Unlink source reference to inode if still around. If a
  1103	 *    directory was moved and the parent of the destination
  1104	 *    is different from the source, patch the ".." entry in the
  1105	 *    directory.
  1106	 */
  1107	static int
  1108	ufs_rename(ap)
  1109		struct vop_rename_args  /* {
  1110			struct vnode *a_fdvp;
  1111			struct vnode *a_fvp;
  1112			struct componentname *a_fcnp;
  1113			struct vnode *a_tdvp;
  1114			struct vnode *a_tvp;
  1115			struct componentname *a_tcnp;
  1116		} */ *ap;
  1117	{
  1118		struct vnode *tvp = ap->a_tvp;
  1119		struct vnode *tdvp = ap->a_tdvp;
  1120		struct vnode *fvp = ap->a_fvp;
  1121		struct vnode *fdvp = ap->a_fdvp;
  1122		struct vnode *nvp;
  1123		struct componentname *tcnp = ap->a_tcnp;
  1124		struct componentname *fcnp = ap->a_fcnp;
  1125		struct thread *td = fcnp->cn_thread;
  1126		struct inode *fip, *tip, *tdp, *fdp;
  1127		struct direct newdir;
  1128		off_t endoff;
  1129		int doingdirectory, newparent;
  1130		int error = 0;
  1131		struct mount *mp;
  1132		ino_t ino;
  1133	
  1134	#ifdef INVARIANTS
  1135		if ((tcnp->cn_flags & HASBUF) == 0 ||
  1136		    (fcnp->cn_flags & HASBUF) == 0)
  1137			panic("ufs_rename: no name");
  1138	#endif
  1139		endoff = 0;
  1140		mp = tdvp->v_mount;
  1141		VOP_UNLOCK(tdvp, 0);
  1142		if (tvp && tvp != tdvp)
  1143			VOP_UNLOCK(tvp, 0);
  1144		/*
  1145		 * Check for cross-device rename.
  1146		 */
  1147		if ((fvp->v_mount != tdvp->v_mount) ||
  1148		    (tvp && (fvp->v_mount != tvp->v_mount))) {
  1149			error = EXDEV;
  1150			mp = NULL;
  1151			goto releout;
  1152		}
  1153	relock:
  1154		/* 
  1155		 * We need to acquire 2 to 4 locks depending on whether tvp is NULL
  1156		 * and fdvp and tdvp are the same directory.  Subsequently we need
  1157		 * to double-check all paths and in the directory rename case we
  1158		 * need to verify that we are not creating a directory loop.  To
  1159		 * handle this we acquire all but fdvp using non-blocking
  1160		 * acquisitions.  If we fail to acquire any lock in the path we will
  1161		 * drop all held locks, acquire the new lock in a blocking fashion,
  1162		 * and then release it and restart the rename.  This acquire/release
  1163		 * step ensures that we do not spin on a lock waiting for release.
  1164		 */
  1165		error = vn_lock(fdvp, LK_EXCLUSIVE);
  1166		if (error)
  1167			goto releout;
  1168		if (vn_lock(tdvp, LK_EXCLUSIVE | LK_NOWAIT) != 0) {
  1169			VOP_UNLOCK(fdvp, 0);
  1170			error = vn_lock(tdvp, LK_EXCLUSIVE);
  1171			if (error)
  1172				goto releout;
  1173			VOP_UNLOCK(tdvp, 0);
  1174			atomic_add_int(&rename_restarts, 1);
  1175			goto relock;
  1176		}
  1177		/*
  1178		 * Re-resolve fvp to be certain it still exists and fetch the
  1179		 * correct vnode.
  1180		 */
  1181		error = ufs_lookup_ino(fdvp, NULL, fcnp, &ino);
  1182		if (error) {
  1183			VOP_UNLOCK(fdvp, 0);
  1184			VOP_UNLOCK(tdvp, 0);
  1185			goto releout;
  1186		}
  1187		error = VFS_VGET(mp, ino, LK_EXCLUSIVE | LK_NOWAIT, &nvp);
  1188		if (error) {
  1189			VOP_UNLOCK(fdvp, 0);
  1190			VOP_UNLOCK(tdvp, 0);
  1191			if (error != EBUSY)
  1192				goto releout;
  1193			error = VFS_VGET(mp, ino, LK_EXCLUSIVE, &nvp);
  1194			if (error != 0)
  1195				goto releout;
  1196			VOP_UNLOCK(nvp, 0);
  1197			vrele(fvp);
  1198			fvp = nvp;
  1199			atomic_add_int(&rename_restarts, 1);
  1200			goto relock;
  1201		}
  1202		vrele(fvp);
  1203		fvp = nvp;
  1204		/*
  1205		 * Re-resolve tvp and acquire the vnode lock if present.
  1206		 */
  1207		error = ufs_lookup_ino(tdvp, NULL, tcnp, &ino);
  1208		if (error != 0 && error != EJUSTRETURN) {
  1209			VOP_UNLOCK(fdvp, 0);
  1210			VOP_UNLOCK(tdvp, 0);
  1211			VOP_UNLOCK(fvp, 0);
  1212			goto releout;
  1213		}
  1214		/*
  1215		 * If tvp disappeared we just carry on.
  1216		 */
  1217		if (error == EJUSTRETURN && tvp != NULL) {
  1218			vrele(tvp);
  1219			tvp = NULL;
  1220		}
  1221		/*
  1222		 * Get the tvp ino if the lookup succeeded.  We may have to restart
  1223		 * if the non-blocking acquire fails.
  1224		 */
  1225		if (error == 0) {
  1226			nvp = NULL;
  1227			error = VFS_VGET(mp, ino, LK_EXCLUSIVE | LK_NOWAIT, &nvp);
  1228			if (tvp)
  1229				vrele(tvp);
  1230			tvp = nvp;
  1231			if (error) {
  1232				VOP_UNLOCK(fdvp, 0);
  1233				VOP_UNLOCK(tdvp, 0);
  1234				VOP_UNLOCK(fvp, 0);
  1235				if (error != EBUSY)
  1236					goto releout;
  1237				error = VFS_VGET(mp, ino, LK_EXCLUSIVE, &nvp);
  1238				if (error != 0)
  1239					goto releout;
  1240				vput(nvp);
  1241				atomic_add_int(&rename_restarts, 1);
  1242				goto relock;
  1243			}
  1244		}
  1245		fdp = VTOI(fdvp);
  1246		fip = VTOI(fvp);
  1247		tdp = VTOI(tdvp);
  1248		tip = NULL;
  1249		if (tvp)
  1250			tip = VTOI(tvp);
  1251		if (tvp && ((VTOI(tvp)->i_flags & (NOUNLINK | IMMUTABLE | APPEND)) ||
  1252		    (VTOI(tdvp)->i_flags & APPEND))) {
  1253			error = EPERM;
  1254			goto unlockout;
  1255		}
  1256		/*
  1257		 * Renaming a file to itself has no effect.  The upper layers should
  1258		 * not call us in that case.  However, things could change after
  1259		 * we drop the locks above.
  1260		 */
  1261		if (fvp == tvp) {
  1262			error = 0;
  1263			goto unlockout;
  1264		}
  1265		doingdirectory = 0;
  1266		newparent = 0;
  1267		ino = fip->i_number;
  1268		if (fip->i_nlink >= LINK_MAX) {
  1269			error = EMLINK;
  1270			goto unlockout;
  1271		}
  1272		if ((fip->i_flags & (NOUNLINK | IMMUTABLE | APPEND))
  1273		    || (fdp->i_flags & APPEND)) {
  1274			error = EPERM;
  1275			goto unlockout;
  1276		}
  1277		if ((fip->i_mode & IFMT) == IFDIR) {
  1278			/*
  1279			 * Avoid ".", "..", and aliases of "." for obvious reasons.
  1280			 */
  1281			if ((fcnp->cn_namelen == 1 && fcnp->cn_nameptr[0] == '.') ||
  1282			    fdp == fip ||
  1283			    (fcnp->cn_flags | tcnp->cn_flags) & ISDOTDOT) {
  1284				error = EINVAL;
  1285				goto unlockout;
  1286			}
  1287			if (fdp->i_number != tdp->i_number)
  1288				newparent = tdp->i_number;
  1289			doingdirectory = 1;
  1290		}
  1291		if ((fvp->v_type == VDIR && fvp->v_mountedhere != NULL) ||
  1292		    (tvp != NULL && tvp->v_type == VDIR &&
  1293		    tvp->v_mountedhere != NULL)) {
  1294			error = EXDEV;
  1295			goto unlockout;
  1296		}
  1297	
  1298		/*
  1299		 * If ".." must be changed (ie the directory gets a new
  1300		 * parent) then the source directory must not be in the
  1301		 * directory hierarchy above the target, as this would
  1302		 * orphan everything below the source directory. Also
  1303		 * the user must have write permission in the source so
  1304		 * as to be able to change "..".
  1305		 */
  1306		if (doingdirectory && newparent) {
  1307			error = VOP_ACCESS(fvp, VWRITE, tcnp->cn_cred, tcnp->cn_thread);
  1308			if (error)
  1309				goto unlockout;
  1310			error = ufs_checkpath(ino, fdp->i_number, tdp, tcnp->cn_cred,
  1311			    &ino);
  1312			/*
  1313			 * We encountered a lock that we have to wait for.  Unlock
  1314			 * everything else and VGET before restarting.
  1315			 */
  1316			if (ino) {
  1317				VOP_UNLOCK(fdvp, 0);
  1318				VOP_UNLOCK(fvp, 0);
  1319				VOP_UNLOCK(tdvp, 0);
  1320				if (tvp)
  1321					VOP_UNLOCK(tvp, 0);
  1322				error = VFS_VGET(mp, ino, LK_SHARED, &nvp);
  1323				if (error == 0)
  1324					vput(nvp);
  1325				atomic_add_int(&rename_restarts, 1);
  1326				goto relock;
  1327			}
  1328			if (error)
  1329				goto unlockout;
  1330			if ((tcnp->cn_flags & SAVESTART) == 0)
  1331				panic("ufs_rename: lost to startdir");
  1332		}
  1333		if (fip->i_effnlink == 0 || fdp->i_effnlink == 0 ||
  1334		    tdp->i_effnlink == 0)
  1335			panic("Bad effnlink fip %p, fdp %p, tdp %p", fip, fdp, tdp);
  1336	
  1337		/*
  1338		 * 1) Bump link count while we're moving stuff
  1339		 *    around.  If we crash somewhere before
  1340		 *    completing our work, the link count
  1341		 *    may be wrong, but correctable.
  1342		 */
  1343		fip->i_effnlink++;
  1344		fip->i_nlink++;
  1345		DIP_SET(fip, i_nlink, fip->i_nlink);
  1346		fip->i_flag |= IN_CHANGE;
  1347		if (DOINGSOFTDEP(fvp))
  1348			softdep_setup_link(tdp, fip);
  1349		error = UFS_UPDATE(fvp, !(DOINGSOFTDEP(fvp) | DOINGASYNC(fvp)));
  1350		if (error)
  1351			goto bad;
  1352	
  1353		/*
  1354		 * 2) If target doesn't exist, link the target
  1355		 *    to the source and unlink the source.
  1356		 *    Otherwise, rewrite the target directory
  1357		 *    entry to reference the source inode and
  1358		 *    expunge the original entry's existence.
  1359		 */
  1360		if (tip == NULL) {
  1361			if (ITODEV(tdp) != ITODEV(fip))
  1362				panic("ufs_rename: EXDEV");
  1363			if (doingdirectory && newparent) {
  1364				/*
  1365				 * Account for ".." in new directory.
  1366				 * When source and destination have the same
  1367				 * parent we don't adjust the link count.  The
  1368				 * actual link modification is completed when
  1369				 * .. is rewritten below.
  1370				 */
  1371				if ((nlink_t)tdp->i_nlink >= LINK_MAX) {
  1372					error = EMLINK;
  1373					goto bad;
  1374				}
  1375			}
  1376			ufs_makedirentry(fip, tcnp, &newdir);
  1377			error = ufs_direnter(tdvp, NULL, &newdir, tcnp, NULL, 1);
  1378			if (error)
  1379				goto bad;
  1380			/* Setup tdvp for directory compaction if needed. */
  1381			if (tdp->i_count && tdp->i_endoff &&
  1382			    tdp->i_endoff < tdp->i_size)
  1383				endoff = tdp->i_endoff;
  1384		} else {
  1385			if (ITODEV(tip) != ITODEV(tdp) || ITODEV(tip) != ITODEV(fip))
  1386				panic("ufs_rename: EXDEV");
  1387			/*
  1388			 * Short circuit rename(foo, foo).
  1389			 */
  1390			if (tip->i_number == fip->i_number)
  1391				panic("ufs_rename: same file");
  1392			/*
  1393			 * If the parent directory is "sticky", then the caller
  1394			 * must possess VADMIN for the parent directory, or the
  1395			 * destination of the rename.  This implements append-only
  1396			 * directories.
  1397			 */
  1398			if ((tdp->i_mode & S_ISTXT) &&
  1399			    VOP_ACCESS(tdvp, VADMIN, tcnp->cn_cred, td) &&
  1400			    VOP_ACCESS(tvp, VADMIN, tcnp->cn_cred, td)) {
  1401				error = EPERM;
  1402				goto bad;
  1403			}
  1404			/*
  1405			 * Target must be empty if a directory and have no links
  1406			 * to it. Also, ensure source and target are compatible
  1407			 * (both directories, or both not directories).
  1408			 */
  1409			if ((tip->i_mode & IFMT) == IFDIR) {
  1410				if ((tip->i_effnlink > 2) ||
  1411				    !ufs_dirempty(tip, tdp->i_number, tcnp->cn_cred)) {
  1412					error = ENOTEMPTY;
  1413					goto bad;
  1414				}
  1415				if (!doingdirectory) {
  1416					error = ENOTDIR;
  1417					goto bad;
  1418				}
  1419				cache_purge(tdvp);
  1420			} else if (doingdirectory) {
  1421				error = EISDIR;
  1422				goto bad;
  1423			}
  1424			if (doingdirectory) {
  1425				if (!newparent) {
  1426					tdp->i_effnlink--;
  1427					if (DOINGSOFTDEP(tdvp))
  1428						softdep_change_linkcnt(tdp);
  1429				}
  1430				tip->i_effnlink--;
  1431				if (DOINGSOFTDEP(tvp))
  1432					softdep_change_linkcnt(tip);
  1433			}
  1434			error = ufs_dirrewrite(tdp, tip, fip->i_number,
  1435			    IFTODT(fip->i_mode),
  1436			    (doingdirectory && newparent) ? newparent : doingdirectory);
  1437			if (error) {
  1438				if (doingdirectory) {
  1439					if (!newparent) {
  1440						tdp->i_effnlink++;
  1441						if (DOINGSOFTDEP(tdvp))
  1442							softdep_change_linkcnt(tdp);
  1443					}
  1444					tip->i_effnlink++;
  1445					if (DOINGSOFTDEP(tvp))
  1446						softdep_change_linkcnt(tip);
  1447				}
  1448			}
  1449			if (doingdirectory && !DOINGSOFTDEP(tvp)) {
  1450				/*
  1451				 * The only stuff left in the directory is "."
  1452				 * and "..". The "." reference is inconsequential
  1453				 * since we are quashing it. We have removed the "."
  1454				 * reference and the reference in the parent directory,
  1455				 * but there may be other hard links. The soft
  1456				 * dependency code will arrange to do these operations
  1457				 * after the parent directory entry has been deleted on
  1458				 * disk, so when running with that code we avoid doing
  1459				 * them now.
  1460				 */
  1461				if (!newparent) {
  1462					tdp->i_nlink--;
  1463					DIP_SET(tdp, i_nlink, tdp->i_nlink);
  1464					tdp->i_flag |= IN_CHANGE;
  1465				}
  1466				tip->i_nlink--;
  1467				DIP_SET(tip, i_nlink, tip->i_nlink);
  1468				tip->i_flag |= IN_CHANGE;
  1469			}
  1470		}
  1471	
  1472		/*
  1473		 * 3) Unlink the source.  We have to resolve the path again to
  1474		 * fixup the directory offset and count for ufs_dirremove.
  1475		 */
  1476		if (fdvp == tdvp) {
  1477			error = ufs_lookup_ino(fdvp, NULL, fcnp, &ino);
  1478			if (error)
  1479				panic("ufs_rename: from entry went away!");
  1480			if (ino != fip->i_number)
  1481				panic("ufs_rename: ino mismatch %ju != %ju\n",
  1482				    (uintmax_t)ino, (uintmax_t)fip->i_number);
  1483		}
  1484		/*
  1485		 * If the source is a directory with a
  1486		 * new parent, the link count of the old
  1487		 * parent directory must be decremented
  1488		 * and ".." set to point to the new parent.
  1489		 */
  1490		if (doingdirectory && newparent) {
  1491			/*
  1492			 * If tip exists we simply use its link, otherwise we must
  1493			 * add a new one.
  1494			 */
  1495			if (tip == NULL) {
  1496				tdp->i_effnlink++;
  1497				tdp->i_nlink++;
  1498				DIP_SET(tdp, i_nlink, tdp->i_nlink);
  1499				tdp->i_flag |= IN_CHANGE;
  1500				if (DOINGSOFTDEP(tdvp))
  1501					softdep_setup_dotdot_link(tdp, fip);
  1502				error = UFS_UPDATE(tdvp, !(DOINGSOFTDEP(tdvp) |
  1503							   DOINGASYNC(tdvp)));
  1504				/* Don't go to bad here as the new link exists. */
  1505				if (error)
  1506					goto unlockout;
  1507			} else if (DOINGSUJ(tdvp))
  1508				/* Journal must account for each new link. */
  1509				softdep_setup_dotdot_link(tdp, fip);
  1510			fip->i_offset = mastertemplate.dot_reclen;
  1511			ufs_dirrewrite(fip, fdp, newparent, DT_DIR, 0);
  1512			cache_purge(fdvp);
  1513		}
  1514		error = ufs_dirremove(fdvp, fip, fcnp->cn_flags, 0);
  1515		/*
  1516		 * The kern_renameat() looks up the fvp using the DELETE flag, which
  1517		 * causes the removal of the name cache entry for fvp.
  1518		 * As the relookup of the fvp is done in two steps:
  1519		 * ufs_lookup_ino() and then VFS_VGET(), another thread might do a
  1520		 * normal lookup of the from name just before the VFS_VGET() call,
  1521		 * causing the cache entry to be re-instantiated.
  1522		 *
  1523		 * The same issue also applies to tvp if it exists as
  1524		 * otherwise we may have a stale name cache entry for the new
  1525		 * name that references the old i-node if it has other links
  1526		 * or open file descriptors.
  1527		 */
  1528		cache_purge(fvp);
  1529		if (tvp)
  1530			cache_purge(tvp);
  1531		cache_purge_negative(tdvp);
  1532	
  1533	unlockout:
  1534		vput(fdvp);
  1535		vput(fvp);
  1536		if (tvp)
  1537			vput(tvp);
  1538		/*
  1539		 * If compaction or fsync was requested do it now that other locks
  1540		 * are no longer needed.
  1541		 */
  1542		if (error == 0 && endoff != 0) {
  1543			error = UFS_TRUNCATE(tdvp, endoff, IO_NORMAL | IO_SYNC,
  1544			    tcnp->cn_cred);
  1545			if (error != 0)
  1546				vn_printf(tdvp,
  1547				    "ufs_rename: failed to truncate, error %d\n",
  1548				    error);
  1549	#ifdef UFS_DIRHASH
  1550			else if (tdp->i_dirhash != NULL)
  1551				ufsdirhash_dirtrunc(tdp, endoff);
  1552	#endif
  1553			/*
  1554			 * Even if the directory compaction failed, rename was
  1555			 * succesful.  Do not propagate a UFS_TRUNCATE() error
  1556			 * to the caller.
  1557			 */
  1558			error = 0;
  1559		}
  1560		if (error == 0 && tdp->i_flag & IN_NEEDSYNC)
  1561			error = VOP_FSYNC(tdvp, MNT_WAIT, td);
  1562		vput(tdvp);
  1563		return (error);
  1564	
  1565	bad:
  1566		fip->i_effnlink--;
  1567		fip->i_nlink--;
  1568		DIP_SET(fip, i_nlink, fip->i_nlink);
  1569		fip->i_flag |= IN_CHANGE;
  1570		if (DOINGSOFTDEP(fvp))
  1571			softdep_revert_link(tdp, fip);
  1572		goto unlockout;
  1573	
  1574	releout:
  1575		vrele(fdvp);
  1576		vrele(fvp);
  1577		vrele(tdvp);
  1578		if (tvp)
  1579			vrele(tvp);
  1580	
  1581		return (error);
  1582	}
  1583	
  1584	#ifdef UFS_ACL
  1585	static int
  1586	ufs_do_posix1e_acl_inheritance_dir(struct vnode *dvp, struct vnode *tvp,
  1587	    mode_t dmode, struct ucred *cred, struct thread *td)
  1588	{
  1589		int error;
  1590		struct inode *ip = VTOI(tvp);
  1591		struct acl *dacl, *acl;
  1592	
  1593		acl = acl_alloc(M_WAITOK);
  1594		dacl = acl_alloc(M_WAITOK);
  1595	
  1596		/*
  1597		 * Retrieve default ACL from parent, if any.
  1598		 */
  1599		error = VOP_GETACL(dvp, ACL_TYPE_DEFAULT, acl, cred, td);
  1600		switch (error) {
  1601		case 0:
  1602			/*
  1603			 * Retrieved a default ACL, so merge mode and ACL if
  1604			 * necessary.  If the ACL is empty, fall through to
  1605			 * the "not defined or available" case.
  1606			 */
  1607			if (acl->acl_cnt != 0) {
  1608				dmode = acl_posix1e_newfilemode(dmode, acl);
  1609				ip->i_mode = dmode;
  1610				DIP_SET(ip, i_mode, dmode);
  1611				*dacl = *acl;
  1612				ufs_sync_acl_from_inode(ip, acl);
  1613				break;
  1614			}
  1615			/* FALLTHROUGH */
  1616	
  1617		case EOPNOTSUPP:
  1618			/*
  1619			 * Just use the mode as-is.
  1620			 */
  1621			ip->i_mode = dmode;
  1622			DIP_SET(ip, i_mode, dmode);
  1623			error = 0;
  1624			goto out;
  1625		
  1626		default:
  1627			goto out;
  1628		}
  1629	
  1630		/*
  1631		 * XXX: If we abort now, will Soft Updates notify the extattr
  1632		 * code that the EAs for the file need to be released?
  1633		 */
  1634		error = VOP_SETACL(tvp, ACL_TYPE_ACCESS, acl, cred, td);
  1635		if (error == 0)
  1636			error = VOP_SETACL(tvp, ACL_TYPE_DEFAULT, dacl, cred, td);
  1637		switch (error) {
  1638		case 0:
  1639			break;
  1640	
  1641		case EOPNOTSUPP:
  1642			/*
  1643			 * XXX: This should not happen, as EOPNOTSUPP above
  1644			 * was supposed to free acl.
  1645			 */
  1646			printf("ufs_mkdir: VOP_GETACL() but no VOP_SETACL()\n");
  1647			/*
  1648			panic("ufs_mkdir: VOP_GETACL() but no VOP_SETACL()");
  1649			 */
  1650			break;
  1651	
  1652		default:
  1653			goto out;
  1654		}
  1655	
  1656	out:
  1657		acl_free(acl);
  1658		acl_free(dacl);
  1659	
  1660		return (error);
  1661	}
  1662	
  1663	static int
  1664	ufs_do_posix1e_acl_inheritance_file(struct vnode *dvp, struct vnode *tvp,
  1665	    mode_t mode, struct ucred *cred, struct thread *td)
  1666	{
  1667		int error;
  1668		struct inode *ip = VTOI(tvp);
  1669		struct acl *acl;
  1670	
  1671		acl = acl_alloc(M_WAITOK);
  1672	
  1673		/*
  1674		 * Retrieve default ACL for parent, if any.
  1675		 */
  1676		error = VOP_GETACL(dvp, ACL_TYPE_DEFAULT, acl, cred, td);
  1677		switch (error) {
  1678		case 0:
  1679			/*
  1680			 * Retrieved a default ACL, so merge mode and ACL if
  1681			 * necessary.
  1682			 */
  1683			if (acl->acl_cnt != 0) {
  1684				/*
  1685				 * Two possible ways for default ACL to not
  1686				 * be present.  First, the EA can be
  1687				 * undefined, or second, the default ACL can
  1688				 * be blank.  If it's blank, fall through to
  1689				 * the it's not defined case.
  1690				 */
  1691				mode = acl_posix1e_newfilemode(mode, acl);
  1692				ip->i_mode = mode;
  1693				DIP_SET(ip, i_mode, mode);
  1694				ufs_sync_acl_from_inode(ip, acl);
  1695				break;
  1696			}
  1697			/* FALLTHROUGH */
  1698	
  1699		case EOPNOTSUPP:
  1700			/*
  1701			 * Just use the mode as-is.
  1702			 */
  1703			ip->i_mode = mode;
  1704			DIP_SET(ip, i_mode, mode);
  1705			error = 0;
  1706			goto out;
  1707	
  1708		default:
  1709			goto out;
  1710		}
  1711	
  1712		/*
  1713		 * XXX: If we abort now, will Soft Updates notify the extattr
  1714		 * code that the EAs for the file need to be released?
  1715		 */
  1716		error = VOP_SETACL(tvp, ACL_TYPE_ACCESS, acl, cred, td);
  1717		switch (error) {
  1718		case 0:
  1719			break;
  1720	
  1721		case EOPNOTSUPP:
  1722			/*
  1723			 * XXX: This should not happen, as EOPNOTSUPP above was
  1724			 * supposed to free acl.
  1725			 */
  1726			printf("ufs_do_posix1e_acl_inheritance_file: VOP_GETACL() "
  1727			    "but no VOP_SETACL()\n");
  1728			/* panic("ufs_do_posix1e_acl_inheritance_file: VOP_GETACL() "
  1729			    "but no VOP_SETACL()"); */
  1730			break;
  1731	
  1732		default:
  1733			goto out;
  1734		}
  1735	
  1736	out:
  1737		acl_free(acl);
  1738	
  1739		return (error);
  1740	}
  1741	
  1742	static int
  1743	ufs_do_nfs4_acl_inheritance(struct vnode *dvp, struct vnode *tvp,
  1744	    mode_t child_mode, struct ucred *cred, struct thread *td)
  1745	{
  1746		int error;
  1747		struct acl *parent_aclp, *child_aclp;
  1748	
  1749		parent_aclp = acl_alloc(M_WAITOK);
  1750		child_aclp = acl_alloc(M_WAITOK | M_ZERO);
  1751	
  1752		error = ufs_getacl_nfs4_internal(dvp, parent_aclp, td);
  1753		if (error)
  1754			goto out;
  1755		acl_nfs4_compute_inherited_acl(parent_aclp, child_aclp,
  1756		    child_mode, VTOI(tvp)->i_uid, tvp->v_type == VDIR);
  1757		error = ufs_setacl_nfs4_internal(tvp, child_aclp, td);
  1758		if (error)
  1759			goto out;
  1760	out:
  1761		acl_free(parent_aclp);
  1762		acl_free(child_aclp);
  1763	
  1764		return (error);
  1765	}
  1766	#endif
  1767	
  1768	/*
  1769	 * Mkdir system call
  1770	 */
  1771	static int
  1772	ufs_mkdir(ap)
  1773		struct vop_mkdir_args /* {
  1774			struct vnode *a_dvp;
  1775			struct vnode **a_vpp;
  1776			struct componentname *a_cnp;
  1777			struct vattr *a_vap;
  1778		} */ *ap;
  1779	{
  1780		struct vnode *dvp = ap->a_dvp;
  1781		struct vattr *vap = ap->a_vap;
  1782		struct componentname *cnp = ap->a_cnp;
  1783		struct inode *ip, *dp;
  1784		struct vnode *tvp;
  1785		struct buf *bp;
  1786		struct dirtemplate dirtemplate, *dtp;
  1787		struct direct newdir;
  1788		int error, dmode;
  1789		long blkoff;
  1790	
  1791	#ifdef INVARIANTS
  1792		if ((cnp->cn_flags & HASBUF) == 0)
  1793			panic("ufs_mkdir: no name");
  1794	#endif
  1795		dp = VTOI(dvp);
  1796		if ((nlink_t)dp->i_nlink >= LINK_MAX) {
  1797			error = EMLINK;
  1798			goto out;
  1799		}
  1800		dmode = vap->va_mode & 0777;
  1801		dmode |= IFDIR;
  1802		/*
  1803		 * Must simulate part of ufs_makeinode here to acquire the inode,
  1804		 * but not have it entered in the parent directory. The entry is
  1805		 * made later after writing "." and ".." entries.
  1806		 */
  1807		if (dp->i_effnlink < 2) {
  1808			print_bad_link_count("ufs_mkdir", dvp);
  1809			error = EINVAL;
  1810			goto out;
  1811		}
  1812		error = UFS_VALLOC(dvp, dmode, cnp->cn_cred, &tvp);
  1813		if (error)
  1814			goto out;
  1815		ip = VTOI(tvp);
  1816		ip->i_gid = dp->i_gid;
  1817		DIP_SET(ip, i_gid, dp->i_gid);
  1818	#ifdef SUIDDIR
  1819		{
  1820	#ifdef QUOTA
  1821			struct ucred ucred, *ucp;
  1822			gid_t ucred_group;
  1823			ucp = cnp->cn_cred;
  1824	#endif
  1825			/*
  1826			 * If we are hacking owners here, (only do this where told to)
  1827			 * and we are not giving it TO root, (would subvert quotas)
  1828			 * then go ahead and give it to the other user.
  1829			 * The new directory also inherits the SUID bit.
  1830			 * If user's UID and dir UID are the same,
  1831			 * 'give it away' so that the SUID is still forced on.
  1832			 */
  1833			if ((dvp->v_mount->mnt_flag & MNT_SUIDDIR) &&
  1834			    (dp->i_mode & ISUID) && dp->i_uid) {
  1835				dmode |= ISUID;
  1836				ip->i_uid = dp->i_uid;
  1837				DIP_SET(ip, i_uid, dp->i_uid);
  1838	#ifdef QUOTA
  1839				if (dp->i_uid != cnp->cn_cred->cr_uid) {
  1840					/*
  1841					 * Make sure the correct user gets charged
  1842					 * for the space.
  1843					 * Make a dummy credential for the victim.
  1844					 * XXX This seems to never be accessed out of
  1845					 * our context so a stack variable is ok.
  1846					 */
  1847					refcount_init(&ucred.cr_ref, 1);
  1848					ucred.cr_uid = ip->i_uid;
  1849					ucred.cr_ngroups = 1;
  1850					ucred.cr_groups = &ucred_group;
  1851					ucred.cr_groups[0] = dp->i_gid;
  1852					ucp = &ucred;
  1853				}
  1854	#endif
  1855			} else {
  1856				ip->i_uid = cnp->cn_cred->cr_uid;
  1857				DIP_SET(ip, i_uid, ip->i_uid);
  1858			}
  1859	#ifdef QUOTA
  1860			if ((error = getinoquota(ip)) ||
  1861		    	    (error = chkiq(ip, 1, ucp, 0))) {
  1862				if (DOINGSOFTDEP(tvp))
  1863					softdep_revert_link(dp, ip);
  1864				UFS_VFREE(tvp, ip->i_number, dmode);
  1865				vput(tvp);
  1866				return (error);
  1867			}
  1868	#endif
  1869		}
  1870	#else	/* !SUIDDIR */
  1871		ip->i_uid = cnp->cn_cred->cr_uid;
  1872		DIP_SET(ip, i_uid, ip->i_uid);
  1873	#ifdef QUOTA
  1874		if ((error = getinoquota(ip)) ||
  1875		    (error = chkiq(ip, 1, cnp->cn_cred, 0))) {
  1876			if (DOINGSOFTDEP(tvp))
  1877				softdep_revert_link(dp, ip);
  1878			UFS_VFREE(tvp, ip->i_number, dmode);
  1879			vput(tvp);
  1880			return (error);
  1881		}
  1882	#endif
  1883	#endif	/* !SUIDDIR */
  1884		ip->i_flag |= IN_ACCESS | IN_CHANGE | IN_UPDATE;
  1885		ip->i_mode = dmode;
  1886		DIP_SET(ip, i_mode, dmode);
  1887		tvp->v_type = VDIR;	/* Rest init'd in getnewvnode(). */
  1888		ip->i_effnlink = 2;
  1889		ip->i_nlink = 2;
  1890		DIP_SET(ip, i_nlink, 2);
  1891	
  1892		if (cnp->cn_flags & ISWHITEOUT) {
  1893			ip->i_flags |= UF_OPAQUE;
  1894			DIP_SET(ip, i_flags, ip->i_flags);
  1895		}
  1896	
  1897		/*
  1898		 * Bump link count in parent directory to reflect work done below.
  1899		 * Should be done before reference is created so cleanup is
  1900		 * possible if we crash.
  1901		 */
  1902		dp->i_effnlink++;
  1903		dp->i_nlink++;
  1904		DIP_SET(dp, i_nlink, dp->i_nlink);
  1905		dp->i_flag |= IN_CHANGE;
  1906		if (DOINGSOFTDEP(dvp))
  1907			softdep_setup_mkdir(dp, ip);
  1908		error = UFS_UPDATE(dvp, !(DOINGSOFTDEP(dvp) | DOINGASYNC(dvp)));
  1909		if (error)
  1910			goto bad;
  1911	#ifdef MAC
  1912		if (dvp->v_mount->mnt_flag & MNT_MULTILABEL) {
  1913			error = mac_vnode_create_extattr(cnp->cn_cred, dvp->v_mount,
  1914			    dvp, tvp, cnp);
  1915			if (error)
  1916				goto bad;
  1917		}
  1918	#endif
  1919	#ifdef UFS_ACL
  1920		if (dvp->v_mount->mnt_flag & MNT_ACLS) {
  1921			error = ufs_do_posix1e_acl_inheritance_dir(dvp, tvp, dmode,
  1922			    cnp->cn_cred, cnp->cn_thread);
  1923			if (error)
  1924				goto bad;
  1925		} else if (dvp->v_mount->mnt_flag & MNT_NFS4ACLS) {
  1926			error = ufs_do_nfs4_acl_inheritance(dvp, tvp, dmode,
  1927			    cnp->cn_cred, cnp->cn_thread);
  1928			if (error)
  1929				goto bad;
  1930		}
  1931	#endif /* !UFS_ACL */
  1932	
  1933		/*
  1934		 * Initialize directory with "." and ".." from static template.
  1935		 */
  1936		if (dvp->v_mount->mnt_maxsymlinklen > 0)
  1937			dtp = &mastertemplate;
  1938		else
  1939			dtp = (struct dirtemplate *)&omastertemplate;
  1940		dirtemplate = *dtp;
  1941		dirtemplate.dot_ino = ip->i_number;
  1942		dirtemplate.dotdot_ino = dp->i_number;
  1943		vnode_pager_setsize(tvp, DIRBLKSIZ);
  1944		if ((error = UFS_BALLOC(tvp, (off_t)0, DIRBLKSIZ, cnp->cn_cred,
  1945		    BA_CLRBUF, &bp)) != 0)
  1946			goto bad;
  1947		ip->i_size = DIRBLKSIZ;
  1948		DIP_SET(ip, i_size, DIRBLKSIZ);
  1949		ip->i_flag |= IN_CHANGE | IN_UPDATE;
  1950		bcopy((caddr_t)&dirtemplate, (caddr_t)bp->b_data, sizeof dirtemplate);
  1951		if (DOINGSOFTDEP(tvp)) {
  1952			/*
  1953			 * Ensure that the entire newly allocated block is a
  1954			 * valid directory so that future growth within the
  1955			 * block does not have to ensure that the block is
  1956			 * written before the inode.
  1957			 */
  1958			blkoff = DIRBLKSIZ;
  1959			while (blkoff < bp->b_bcount) {
  1960				((struct direct *)
  1961				   (bp->b_data + blkoff))->d_reclen = DIRBLKSIZ;
  1962				blkoff += DIRBLKSIZ;
  1963			}
  1964		}
  1965		if ((error = UFS_UPDATE(tvp, !(DOINGSOFTDEP(tvp) |
  1966					       DOINGASYNC(tvp)))) != 0) {
  1967			(void)bwrite(bp);
  1968			goto bad;
  1969		}
  1970		/*
  1971		 * Directory set up, now install its entry in the parent directory.
  1972		 *
  1973		 * If we are not doing soft dependencies, then we must write out the
  1974		 * buffer containing the new directory body before entering the new 
  1975		 * name in the parent. If we are doing soft dependencies, then the
  1976		 * buffer containing the new directory body will be passed to and
  1977		 * released in the soft dependency code after the code has attached
  1978		 * an appropriate ordering dependency to the buffer which ensures that
  1979		 * the buffer is written before the new name is written in the parent.
  1980		 */
  1981		if (DOINGASYNC(dvp))
  1982			bdwrite(bp);
  1983		else if (!DOINGSOFTDEP(dvp) && ((error = bwrite(bp))))
  1984			goto bad;
  1985		ufs_makedirentry(ip, cnp, &newdir);
  1986		error = ufs_direnter(dvp, tvp, &newdir, cnp, bp, 0);
  1987		
  1988	bad:
  1989		if (error == 0) {
  1990			*ap->a_vpp = tvp;
  1991		} else {
  1992			dp->i_effnlink--;
  1993			dp->i_nlink--;
  1994			DIP_SET(dp, i_nlink, dp->i_nlink);
  1995			dp->i_flag |= IN_CHANGE;
  1996			/*
  1997			 * No need to do an explicit VOP_TRUNCATE here, vrele will
  1998			 * do this for us because we set the link count to 0.
  1999			 */
  2000			ip->i_effnlink = 0;
  2001			ip->i_nlink = 0;
  2002			DIP_SET(ip, i_nlink, 0);
  2003			ip->i_flag |= IN_CHANGE;
  2004			if (DOINGSOFTDEP(tvp))
  2005				softdep_revert_mkdir(dp, ip);
  2006	
  2007			vput(tvp);
  2008		}
  2009	out:
  2010		return (error);
  2011	}
  2012	
  2013	/*
  2014	 * Rmdir system call.
  2015	 */
  2016	static int
  2017	ufs_rmdir(ap)
  2018		struct vop_rmdir_args /* {
  2019			struct vnode *a_dvp;
  2020			struct vnode *a_vp;
  2021			struct componentname *a_cnp;
  2022		} */ *ap;
  2023	{
  2024		struct vnode *vp = ap->a_vp;
  2025		struct vnode *dvp = ap->a_dvp;
  2026		struct componentname *cnp = ap->a_cnp;
  2027		struct inode *ip, *dp;
  2028		int error;
  2029	
  2030		ip = VTOI(vp);
  2031		dp = VTOI(dvp);
  2032	
  2033		/*
  2034		 * Do not remove a directory that is in the process of being renamed.
  2035		 * Verify the directory is empty (and valid). Rmdir ".." will not be
  2036		 * valid since ".." will contain a reference to the current directory
  2037		 * and thus be non-empty. Do not allow the removal of mounted on
  2038		 * directories (this can happen when an NFS exported filesystem
  2039		 * tries to remove a locally mounted on directory).
  2040		 */
  2041		error = 0;
  2042		if (dp->i_effnlink <= 2) {
  2043			if (dp->i_effnlink == 2)
  2044				print_bad_link_count("ufs_rmdir", dvp);
  2045			error = EINVAL;
  2046			goto out;
  2047		}
  2048		if (!ufs_dirempty(ip, dp->i_number, cnp->cn_cred)) {
  2049			error = ENOTEMPTY;
  2050			goto out;
  2051		}
  2052		if ((dp->i_flags & APPEND)
  2053		    || (ip->i_flags & (NOUNLINK | IMMUTABLE | APPEND))) {
  2054			error = EPERM;
  2055			goto out;
  2056		}
  2057		if (vp->v_mountedhere != 0) {
  2058			error = EINVAL;
  2059			goto out;
  2060		}
  2061	#ifdef UFS_GJOURNAL
  2062		ufs_gjournal_orphan(vp);
  2063	#endif
  2064		/*
  2065		 * Delete reference to directory before purging
  2066		 * inode.  If we crash in between, the directory
  2067		 * will be reattached to lost+found,
  2068		 */
  2069		dp->i_effnlink--;
  2070		ip->i_effnlink--;
  2071		if (DOINGSOFTDEP(vp))
  2072			softdep_setup_rmdir(dp, ip);
  2073		error = ufs_dirremove(dvp, ip, cnp->cn_flags, 1);
  2074		if (error) {
  2075			dp->i_effnlink++;
  2076			ip->i_effnlink++;
  2077			if (DOINGSOFTDEP(vp))
  2078				softdep_revert_rmdir(dp, ip);
  2079			goto out;
  2080		}
  2081		cache_purge(dvp);
  2082		/*
  2083		 * The only stuff left in the directory is "." and "..". The "."
  2084		 * reference is inconsequential since we are quashing it. The soft
  2085		 * dependency code will arrange to do these operations after
  2086		 * the parent directory entry has been deleted on disk, so
  2087		 * when running with that code we avoid doing them now.
  2088		 */
  2089		if (!DOINGSOFTDEP(vp)) {
  2090			dp->i_nlink--;
  2091			DIP_SET(dp, i_nlink, dp->i_nlink);
  2092			dp->i_flag |= IN_CHANGE;
  2093			error = UFS_UPDATE(dvp, 0);
  2094			ip->i_nlink--;
  2095			DIP_SET(ip, i_nlink, ip->i_nlink);
  2096			ip->i_flag |= IN_CHANGE;
  2097		}
  2098		cache_purge(vp);
  2099	#ifdef UFS_DIRHASH
  2100		/* Kill any active hash; i_effnlink == 0, so it will not come back. */
  2101		if (ip->i_dirhash != NULL)
  2102			ufsdirhash_free(ip);
  2103	#endif
  2104	out:
  2105		return (error);
  2106	}
  2107	
  2108	/*
  2109	 * symlink -- make a symbolic link
  2110	 */
  2111	static int
  2112	ufs_symlink(ap)
  2113		struct vop_symlink_args /* {
  2114			struct vnode *a_dvp;
  2115			struct vnode **a_vpp;
  2116			struct componentname *a_cnp;
  2117			struct vattr *a_vap;
  2118			char *a_target;
  2119		} */ *ap;
  2120	{
  2121		struct vnode *vp, **vpp = ap->a_vpp;
  2122		struct inode *ip;
  2123		int len, error;
  2124	
  2125		error = ufs_makeinode(IFLNK | ap->a_vap->va_mode, ap->a_dvp,
  2126		    vpp, ap->a_cnp, "ufs_symlink");
  2127		if (error)
  2128			return (error);
  2129		vp = *vpp;
  2130		len = strlen(ap->a_target);
  2131		if (len < vp->v_mount->mnt_maxsymlinklen) {
  2132			ip = VTOI(vp);
  2133			bcopy(ap->a_target, SHORTLINK(ip), len);
  2134			ip->i_size = len;
  2135			DIP_SET(ip, i_size, len);
  2136			ip->i_flag |= IN_CHANGE | IN_UPDATE;
  2137			error = UFS_UPDATE(vp, 0);
  2138		} else
  2139			error = vn_rdwr(UIO_WRITE, vp, ap->a_target, len, (off_t)0,
  2140			    UIO_SYSSPACE, IO_NODELOCKED | IO_NOMACCHECK,
  2141			    ap->a_cnp->cn_cred, NOCRED, NULL, NULL);
  2142		if (error)
  2143			vput(vp);
  2144		return (error);
  2145	}
  2146	
  2147	/*
  2148	 * Vnode op for reading directories.
  2149	 */
  2150	int
  2151	ufs_readdir(ap)
  2152		struct vop_readdir_args /* {
  2153			struct vnode *a_vp;
  2154			struct uio *a_uio;
  2155			struct ucred *a_cred;
  2156			int *a_eofflag;
  2157			int *a_ncookies;
  2158			u_long **a_cookies;
  2159		} */ *ap;
  2160	{
  2161		struct vnode *vp = ap->a_vp;
  2162		struct uio *uio = ap->a_uio;
  2163		struct buf *bp;
  2164		struct inode *ip;
  2165		struct direct *dp, *edp;
  2166		u_long *cookies;
  2167		struct dirent dstdp;
  2168		off_t offset, startoffset;
  2169		size_t readcnt, skipcnt;
  2170		ssize_t startresid;
  2171		int ncookies;
  2172		int error;
  2173	
  2174		if (uio->uio_offset < 0)
  2175			return (EINVAL);
  2176		ip = VTOI(vp);
  2177		if (ip->i_effnlink == 0)
  2178			return (0);
  2179		if (ap->a_ncookies != NULL) {
  2180			if (uio->uio_resid < 0)
  2181				ncookies = 0;
  2182			else
  2183				ncookies = uio->uio_resid;
  2184			if (uio->uio_offset >= ip->i_size)
  2185				ncookies = 0;
  2186			else if (ip->i_size - uio->uio_offset < ncookies)
  2187				ncookies = ip->i_size - uio->uio_offset;
  2188			ncookies = ncookies / (offsetof(struct direct, d_name) + 4) + 1;
  2189			cookies = malloc(ncookies * sizeof(*cookies), M_TEMP, M_WAITOK);
  2190			*ap->a_ncookies = ncookies;
  2191			*ap->a_cookies = cookies;
  2192		} else {
  2193			ncookies = 0;
  2194			cookies = NULL;
  2195		}
  2196		offset = startoffset = uio->uio_offset;
  2197		startresid = uio->uio_resid;
  2198		error = 0;
  2199		while (error == 0 && uio->uio_resid > 0 &&
  2200		    uio->uio_offset < ip->i_size) {
  2201			error = ffs_blkatoff(vp, uio->uio_offset, NULL, &bp);
  2202			if (error)
  2203				break;
  2204			if (bp->b_offset + bp->b_bcount > ip->i_size)
  2205				readcnt = ip->i_size - bp->b_offset;
  2206			else
  2207				readcnt = bp->b_bcount;
  2208			skipcnt = (size_t)(uio->uio_offset - bp->b_offset) &
  2209			    ~(size_t)(DIRBLKSIZ - 1);
  2210			offset = bp->b_offset + skipcnt;
  2211			dp = (struct direct *)&bp->b_data[skipcnt];
  2212			edp = (struct direct *)&bp->b_data[readcnt];
  2213			while (error == 0 && uio->uio_resid > 0 && dp < edp) {
  2214				if (dp->d_reclen <= offsetof(struct direct, d_name) ||
  2215				    (caddr_t)dp + dp->d_reclen > (caddr_t)edp) {
  2216					error = EIO;
  2217					break;
  2218				}
  2219	#if BYTE_ORDER == LITTLE_ENDIAN
  2220				/* Old filesystem format. */
  2221				if (vp->v_mount->mnt_maxsymlinklen <= 0) {
  2222					dstdp.d_namlen = dp->d_type;
  2223					dstdp.d_type = dp->d_namlen;
  2224				} else
  2225	#endif
  2226				{
  2227					dstdp.d_namlen = dp->d_namlen;
  2228					dstdp.d_type = dp->d_type;
  2229				}
  2230				if (offsetof(struct direct, d_name) + dstdp.d_namlen >
  2231				    dp->d_reclen) {
  2232					error = EIO;
  2233					break;
  2234				}
  2235				if (offset < startoffset || dp->d_ino == 0)
  2236					goto nextentry;
  2237				dstdp.d_fileno = dp->d_ino;
  2238				dstdp.d_reclen = GENERIC_DIRSIZ(&dstdp);
  2239				bcopy(dp->d_name, dstdp.d_name, dstdp.d_namlen);
  2240				dstdp.d_name[dstdp.d_namlen] = '\0';
  2241				if (dstdp.d_reclen > uio->uio_resid) {
  2242					if (uio->uio_resid == startresid)
  2243						error = EINVAL;
  2244					else
  2245						error = EJUSTRETURN;
  2246					break;
  2247				}
  2248				/* Advance dp. */
  2249				error = uiomove((caddr_t)&dstdp, dstdp.d_reclen, uio);
  2250				if (error)
  2251					break;
  2252				if (cookies != NULL) {
  2253					KASSERT(ncookies > 0,
  2254					    ("ufs_readdir: cookies buffer too small"));
  2255					*cookies = offset + dp->d_reclen;
  2256					cookies++;
  2257					ncookies--;
  2258				}
  2259	nextentry:
  2260				offset += dp->d_reclen;
  2261				dp = (struct direct *)((caddr_t)dp + dp->d_reclen);
  2262			}
  2263			bqrelse(bp);
  2264			uio->uio_offset = offset;
  2265		}
  2266		/* We need to correct uio_offset. */
  2267		uio->uio_offset = offset;
  2268		if (error == EJUSTRETURN)
  2269			error = 0;
  2270		if (ap->a_ncookies != NULL) {
  2271			if (error == 0) {
  2272				ap->a_ncookies -= ncookies;
  2273			} else {
  2274				free(*ap->a_cookies, M_TEMP);
  2275				*ap->a_ncookies = 0;
  2276				*ap->a_cookies = NULL;
  2277			}
  2278		}
  2279		if (error == 0 && ap->a_eofflag)
  2280			*ap->a_eofflag = ip->i_size <= uio->uio_offset;
  2281		return (error);
  2282	}
  2283	
  2284	/*
  2285	 * Return target name of a symbolic link
  2286	 */
  2287	static int
  2288	ufs_readlink(ap)
  2289		struct vop_readlink_args /* {
  2290			struct vnode *a_vp;
  2291			struct uio *a_uio;
  2292			struct ucred *a_cred;
  2293		} */ *ap;
  2294	{
  2295		struct vnode *vp = ap->a_vp;
  2296		struct inode *ip = VTOI(vp);
  2297		doff_t isize;
  2298	
  2299		isize = ip->i_size;
  2300		if ((isize < vp->v_mount->mnt_maxsymlinklen) ||
  2301		    DIP(ip, i_blocks) == 0) { /* XXX - for old fastlink support */
  2302			return (uiomove(SHORTLINK(ip), isize, ap->a_uio));
  2303		}
  2304		return (VOP_READ(vp, ap->a_uio, 0, ap->a_cred));
  2305	}
  2306	
  2307	/*
  2308	 * Calculate the logical to physical mapping if not done already,
  2309	 * then call the device strategy routine.
  2310	 *
  2311	 * In order to be able to swap to a file, the ufs_bmaparray() operation may not
  2312	 * deadlock on memory.  See ufs_bmap() for details.
  2313	 */
  2314	static int
  2315	ufs_strategy(ap)
  2316		struct vop_strategy_args /* {
  2317			struct vnode *a_vp;
  2318			struct buf *a_bp;
  2319		} */ *ap;
  2320	{
  2321		struct buf *bp = ap->a_bp;
  2322		struct vnode *vp = ap->a_vp;
  2323		ufs2_daddr_t blkno;
  2324		int error;
  2325	
  2326		if (bp->b_blkno == bp->b_lblkno) {
  2327			error = ufs_bmaparray(vp, bp->b_lblkno, &blkno, bp, NULL, NULL);
  2328			bp->b_blkno = blkno;
  2329			if (error) {
  2330				bp->b_error = error;
  2331				bp->b_ioflags |= BIO_ERROR;
  2332				bufdone(bp);
  2333				return (0);
  2334			}
  2335			if ((long)bp->b_blkno == -1)
  2336				vfs_bio_clrbuf(bp);
  2337		}
  2338		if ((long)bp->b_blkno == -1) {
  2339			bufdone(bp);
  2340			return (0);
  2341		}
  2342		bp->b_iooffset = dbtob(bp->b_blkno);
  2343		BO_STRATEGY(VFSTOUFS(vp->v_mount)->um_bo, bp);
  2344		return (0);
  2345	}
  2346	
  2347	/*
  2348	 * Print out the contents of an inode.
  2349	 */
  2350	static int
  2351	ufs_print(ap)
  2352		struct vop_print_args /* {
  2353			struct vnode *a_vp;
  2354		} */ *ap;
  2355	{
  2356		struct vnode *vp = ap->a_vp;
  2357		struct inode *ip = VTOI(vp);
  2358	
  2359		printf("\tino %lu, on dev %s", (u_long)ip->i_number,
  2360		    devtoname(ITODEV(ip)));
  2361		if (vp->v_type == VFIFO)
  2362			fifo_printinfo(vp);
  2363		printf("\n");
  2364		return (0);
  2365	}
  2366	
  2367	/*
  2368	 * Close wrapper for fifos.
  2369	 *
  2370	 * Update the times on the inode then do device close.
  2371	 */
  2372	static int
  2373	ufsfifo_close(ap)
  2374		struct vop_close_args /* {
  2375			struct vnode *a_vp;
  2376			int  a_fflag;
  2377			struct ucred *a_cred;
  2378			struct thread *a_td;
  2379		} */ *ap;
  2380	{
  2381		struct vnode *vp = ap->a_vp;
  2382		int usecount;
  2383	
  2384		VI_LOCK(vp);
  2385		usecount = vp->v_usecount;
  2386		if (usecount > 1)
  2387			ufs_itimes_locked(vp);
  2388		VI_UNLOCK(vp);
  2389		return (fifo_specops.vop_close(ap));
  2390	}
  2391	
  2392	/*
  2393	 * Kqfilter wrapper for fifos.
  2394	 *
  2395	 * Fall through to ufs kqfilter routines if needed 
  2396	 */
  2397	static int
  2398	ufsfifo_kqfilter(ap)
  2399		struct vop_kqfilter_args *ap;
  2400	{
  2401		int error;
  2402	
  2403		error = fifo_specops.vop_kqfilter(ap);
  2404		if (error)
  2405			error = vfs_kqfilter(ap);
  2406		return (error);
  2407	}
  2408	
  2409	/*
  2410	 * Return POSIX pathconf information applicable to ufs filesystems.
  2411	 */
  2412	static int
  2413	ufs_pathconf(ap)
  2414		struct vop_pathconf_args /* {
  2415			struct vnode *a_vp;
  2416			int a_name;
  2417			int *a_retval;
  2418		} */ *ap;
  2419	{
  2420		int error;
  2421	
  2422		error = 0;
  2423		switch (ap->a_name) {
  2424		case _PC_NAME_MAX:
  2425			*ap->a_retval = NAME_MAX;
  2426			break;
  2427		case _PC_PIPE_BUF:
  2428			if (ap->a_vp->v_type == VDIR || ap->a_vp->v_type == VFIFO)
  2429				*ap->a_retval = PIPE_BUF;
  2430			else
  2431				error = EINVAL;
  2432			break;
  2433		case _PC_CHOWN_RESTRICTED:
  2434			*ap->a_retval = 1;
  2435			break;
  2436		case _PC_NO_TRUNC:
  2437			*ap->a_retval = 1;
  2438			break;
  2439		case _PC_ACL_EXTENDED:
  2440	#ifdef UFS_ACL
  2441			if (ap->a_vp->v_mount->mnt_flag & MNT_ACLS)
  2442				*ap->a_retval = 1;
  2443			else
  2444				*ap->a_retval = 0;
  2445	#else
  2446			*ap->a_retval = 0;
  2447	#endif
  2448			break;
  2449	
  2450		case _PC_ACL_NFS4:
  2451	#ifdef UFS_ACL
  2452			if (ap->a_vp->v_mount->mnt_flag & MNT_NFS4ACLS)
  2453				*ap->a_retval = 1;
  2454			else
  2455				*ap->a_retval = 0;
  2456	#else
  2457			*ap->a_retval = 0;
  2458	#endif
  2459			break;
  2460	
  2461		case _PC_ACL_PATH_MAX:
  2462	#ifdef UFS_ACL
  2463			if (ap->a_vp->v_mount->mnt_flag & (MNT_ACLS | MNT_NFS4ACLS))
  2464				*ap->a_retval = ACL_MAX_ENTRIES;
  2465			else
  2466				*ap->a_retval = 3;
  2467	#else
  2468			*ap->a_retval = 3;
  2469	#endif
  2470			break;
  2471		case _PC_MAC_PRESENT:
  2472	#ifdef MAC
  2473			if (ap->a_vp->v_mount->mnt_flag & MNT_MULTILABEL)
  2474				*ap->a_retval = 1;
  2475			else
  2476				*ap->a_retval = 0;
  2477	#else
  2478			*ap->a_retval = 0;
  2479	#endif
  2480			break;
  2481		case _PC_MIN_HOLE_SIZE:
  2482			*ap->a_retval = ap->a_vp->v_mount->mnt_stat.f_iosize;
  2483			break;
  2484		case _PC_PRIO_IO:
  2485			*ap->a_retval = 0;
  2486			break;
  2487		case _PC_SYNC_IO:
  2488			*ap->a_retval = 0;
  2489			break;
  2490		case _PC_ALLOC_SIZE_MIN:
  2491			*ap->a_retval = ap->a_vp->v_mount->mnt_stat.f_bsize;
  2492			break;
  2493		case _PC_FILESIZEBITS:
  2494			*ap->a_retval = 64;
  2495			break;
  2496		case _PC_REC_INCR_XFER_SIZE:
  2497			*ap->a_retval = ap->a_vp->v_mount->mnt_stat.f_iosize;
  2498			break;
  2499		case _PC_REC_MAX_XFER_SIZE:
  2500			*ap->a_retval = -1; /* means ``unlimited'' */
  2501			break;
  2502		case _PC_REC_MIN_XFER_SIZE:
  2503			*ap->a_retval = ap->a_vp->v_mount->mnt_stat.f_iosize;
  2504			break;
  2505		case _PC_REC_XFER_ALIGN:
  2506			*ap->a_retval = PAGE_SIZE;
  2507			break;
  2508		case _PC_SYMLINK_MAX:
  2509			*ap->a_retval = MAXPATHLEN;
  2510			break;
  2511	
  2512		default:
  2513			error = vop_stdpathconf(ap);
  2514			break;
  2515		}
  2516		return (error);
  2517	}
  2518	
  2519	/*
  2520	 * Initialize the vnode associated with a new inode, handle aliased
  2521	 * vnodes.
  2522	 */
  2523	int
  2524	ufs_vinit(mntp, fifoops, vpp)
  2525		struct mount *mntp;
  2526		struct vop_vector *fifoops;
  2527		struct vnode **vpp;
  2528	{
  2529		struct inode *ip;
  2530		struct vnode *vp;
  2531	
  2532		vp = *vpp;
  2533		ip = VTOI(vp);
  2534		vp->v_type = IFTOVT(ip->i_mode);
  2535		if (vp->v_type == VFIFO)
  2536			vp->v_op = fifoops;
  2537		ASSERT_VOP_LOCKED(vp, "ufs_vinit");
  2538		if (ip->i_number == ROOTINO)
  2539			vp->v_vflag |= VV_ROOT;
  2540		*vpp = vp;
  2541		return (0);
  2542	}
  2543	
  2544	/*
  2545	 * Allocate a new inode.
  2546	 * Vnode dvp must be locked.
  2547	 */
  2548	static int
  2549	ufs_makeinode(mode, dvp, vpp, cnp, callfunc)
  2550		int mode;
  2551		struct vnode *dvp;
  2552		struct vnode **vpp;
  2553		struct componentname *cnp;
  2554		const char *callfunc;
  2555	{
  2556		struct inode *ip, *pdir;
  2557		struct direct newdir;
  2558		struct vnode *tvp;
  2559		int error;
  2560	
  2561		pdir = VTOI(dvp);
  2562	#ifdef INVARIANTS
  2563		if ((cnp->cn_flags & HASBUF) == 0)
  2564			panic("%s: no name", callfunc);
  2565	#endif
  2566		*vpp = NULL;
  2567		if ((mode & IFMT) == 0)
  2568			mode |= IFREG;
  2569	
  2570		if (pdir->i_effnlink < 2) {
  2571			print_bad_link_count(callfunc, dvp);
  2572			return (EINVAL);
  2573		}
  2574		error = UFS_VALLOC(dvp, mode, cnp->cn_cred, &tvp);
  2575		if (error)
  2576			return (error);
  2577		ip = VTOI(tvp);
  2578		ip->i_gid = pdir->i_gid;
  2579		DIP_SET(ip, i_gid, pdir->i_gid);
  2580	#ifdef SUIDDIR
  2581		{
  2582	#ifdef QUOTA
  2583			struct ucred ucred, *ucp;
  2584			gid_t ucred_group;
  2585			ucp = cnp->cn_cred;
  2586	#endif
  2587			/*
  2588			 * If we are not the owner of the directory,
  2589			 * and we are hacking owners here, (only do this where told to)
  2590			 * and we are not giving it TO root, (would subvert quotas)
  2591			 * then go ahead and give it to the other user.
  2592			 * Note that this drops off the execute bits for security.
  2593			 */
  2594			if ((dvp->v_mount->mnt_flag & MNT_SUIDDIR) &&
  2595			    (pdir->i_mode & ISUID) &&
  2596			    (pdir->i_uid != cnp->cn_cred->cr_uid) && pdir->i_uid) {
  2597				ip->i_uid = pdir->i_uid;
  2598				DIP_SET(ip, i_uid, ip->i_uid);
  2599				mode &= ~07111;
  2600	#ifdef QUOTA
  2601				/*
  2602				 * Make sure the correct user gets charged
  2603				 * for the space.
  2604				 * Quickly knock up a dummy credential for the victim.
  2605				 * XXX This seems to never be accessed out of our
  2606				 * context so a stack variable is ok.
  2607				 */
  2608				refcount_init(&ucred.cr_ref, 1);
  2609				ucred.cr_uid = ip->i_uid;
  2610				ucred.cr_ngroups = 1;
  2611				ucred.cr_groups = &ucred_group;
  2612				ucred.cr_groups[0] = pdir->i_gid;
  2613				ucp = &ucred;
  2614	#endif
  2615			} else {
  2616				ip->i_uid = cnp->cn_cred->cr_uid;
  2617				DIP_SET(ip, i_uid, ip->i_uid);
  2618			}
  2619	
  2620	#ifdef QUOTA
  2621			if ((error = getinoquota(ip)) ||
  2622		    	    (error = chkiq(ip, 1, ucp, 0))) {
  2623				if (DOINGSOFTDEP(tvp))
  2624					softdep_revert_link(pdir, ip);
  2625				UFS_VFREE(tvp, ip->i_number, mode);
  2626				vput(tvp);
  2627				return (error);
  2628			}
  2629	#endif
  2630		}
  2631	#else	/* !SUIDDIR */
  2632		ip->i_uid = cnp->cn_cred->cr_uid;
  2633		DIP_SET(ip, i_uid, ip->i_uid);
  2634	#ifdef QUOTA
  2635		if ((error = getinoquota(ip)) ||
  2636		    (error = chkiq(ip, 1, cnp->cn_cred, 0))) {
  2637			if (DOINGSOFTDEP(tvp))
  2638				softdep_revert_link(pdir, ip);
  2639			UFS_VFREE(tvp, ip->i_number, mode);
  2640			vput(tvp);
  2641			return (error);
  2642		}
  2643	#endif
  2644	#endif	/* !SUIDDIR */
  2645		ip->i_flag |= IN_ACCESS | IN_CHANGE | IN_UPDATE;
  2646		ip->i_mode = mode;
  2647		DIP_SET(ip, i_mode, mode);
  2648		tvp->v_type = IFTOVT(mode);	/* Rest init'd in getnewvnode(). */
  2649		ip->i_effnlink = 1;
  2650		ip->i_nlink = 1;
  2651		DIP_SET(ip, i_nlink, 1);
  2652		if (DOINGSOFTDEP(tvp))
  2653			softdep_setup_create(VTOI(dvp), ip);
  2654		if ((ip->i_mode & ISGID) && !groupmember(ip->i_gid, cnp->cn_cred) &&
  2655		    priv_check_cred(cnp->cn_cred, PRIV_VFS_SETGID, 0)) {
  2656			ip->i_mode &= ~ISGID;
  2657			DIP_SET(ip, i_mode, ip->i_mode);
  2658		}
  2659	
  2660		if (cnp->cn_flags & ISWHITEOUT) {
  2661			ip->i_flags |= UF_OPAQUE;
  2662			DIP_SET(ip, i_flags, ip->i_flags);
  2663		}
  2664	
  2665		/*
  2666		 * Make sure inode goes to disk before directory entry.
  2667		 */
  2668		error = UFS_UPDATE(tvp, !(DOINGSOFTDEP(tvp) | DOINGASYNC(tvp)));
  2669		if (error)
  2670			goto bad;
  2671	#ifdef MAC
  2672		if (dvp->v_mount->mnt_flag & MNT_MULTILABEL) {
  2673			error = mac_vnode_create_extattr(cnp->cn_cred, dvp->v_mount,
  2674			    dvp, tvp, cnp);
  2675			if (error)
  2676				goto bad;
  2677		}
  2678	#endif
  2679	#ifdef UFS_ACL
  2680		if (dvp->v_mount->mnt_flag & MNT_ACLS) {
  2681			error = ufs_do_posix1e_acl_inheritance_file(dvp, tvp, mode,
  2682			    cnp->cn_cred, cnp->cn_thread);
  2683			if (error)
  2684				goto bad;
  2685		} else if (dvp->v_mount->mnt_flag & MNT_NFS4ACLS) {
  2686			error = ufs_do_nfs4_acl_inheritance(dvp, tvp, mode,
  2687			    cnp->cn_cred, cnp->cn_thread);
  2688			if (error)
  2689				goto bad;
  2690		}
  2691	#endif /* !UFS_ACL */
  2692		ufs_makedirentry(ip, cnp, &newdir);
  2693		error = ufs_direnter(dvp, tvp, &newdir, cnp, NULL, 0);
  2694		if (error)
  2695			goto bad;
  2696		*vpp = tvp;
  2697		return (0);
  2698	
  2699	bad:
  2700		/*
  2701		 * Write error occurred trying to update the inode
  2702		 * or the directory so must deallocate the inode.
  2703		 */
  2704		ip->i_effnlink = 0;
  2705		ip->i_nlink = 0;
  2706		DIP_SET(ip, i_nlink, 0);
  2707		ip->i_flag |= IN_CHANGE;
  2708		if (DOINGSOFTDEP(tvp))
  2709			softdep_revert_create(VTOI(dvp), ip);
  2710		vput(tvp);
  2711		return (error);
  2712	}
  2713	
  2714	static int
  2715	ufs_ioctl(struct vop_ioctl_args *ap)
  2716	{
  2717	
  2718		switch (ap->a_command) {
  2719		case FIOSEEKDATA:
  2720		case FIOSEEKHOLE:
  2721			return (vn_bmap_seekhole(ap->a_vp, ap->a_command,
  2722			    (off_t *)ap->a_data, ap->a_cred));
  2723		default:
  2724			return (ENOTTY);
  2725		}
  2726	}
  2727	
  2728	/* Global vfs data structures for ufs. */
  2729	struct vop_vector ufs_vnodeops = {
  2730		.vop_default =		&default_vnodeops,
  2731		.vop_fsync =		VOP_PANIC,
  2732		.vop_read =		VOP_PANIC,
  2733		.vop_reallocblks =	VOP_PANIC,
  2734		.vop_write =		VOP_PANIC,
  2735		.vop_accessx =		ufs_accessx,
  2736		.vop_bmap =		ufs_bmap,
  2737		.vop_cachedlookup =	ufs_lookup,
  2738		.vop_close =		ufs_close,
  2739		.vop_create =		ufs_create,
  2740		.vop_getattr =		ufs_getattr,
  2741		.vop_inactive =		ufs_inactive,
  2742		.vop_ioctl =		ufs_ioctl,
  2743		.vop_link =		ufs_link,
  2744		.vop_lookup =		vfs_cache_lookup,
  2745		.vop_markatime =	ufs_markatime,
  2746		.vop_mkdir =		ufs_mkdir,
  2747		.vop_mknod =		ufs_mknod,
  2748		.vop_open =		ufs_open,
  2749		.vop_pathconf =		ufs_pathconf,
  2750		.vop_poll =		vop_stdpoll,
  2751		.vop_print =		ufs_print,
  2752		.vop_readdir =		ufs_readdir,
  2753		.vop_readlink =		ufs_readlink,
  2754		.vop_reclaim =		ufs_reclaim,
  2755		.vop_remove =		ufs_remove,
  2756		.vop_rename =		ufs_rename,
  2757		.vop_rmdir =		ufs_rmdir,
  2758		.vop_setattr =		ufs_setattr,
  2759	#ifdef MAC
  2760		.vop_setlabel =		vop_stdsetlabel_ea,
  2761	#endif
  2762		.vop_strategy =		ufs_strategy,
  2763		.vop_symlink =		ufs_symlink,
  2764		.vop_whiteout =		ufs_whiteout,
  2765	#ifdef UFS_EXTATTR
  2766		.vop_getextattr =	ufs_getextattr,
  2767		.vop_deleteextattr =	ufs_deleteextattr,
  2768		.vop_setextattr =	ufs_setextattr,
  2769	#endif
  2770	#ifdef UFS_ACL
  2771		.vop_getacl =		ufs_getacl,
  2772		.vop_setacl =		ufs_setacl,
  2773		.vop_aclcheck =		ufs_aclcheck,
  2774	#endif
  2775	};
  2776	
  2777	struct vop_vector ufs_fifoops = {
  2778		.vop_default =		&fifo_specops,
  2779		.vop_fsync =		VOP_PANIC,
  2780		.vop_accessx =		ufs_accessx,
  2781		.vop_close =		ufsfifo_close,
  2782		.vop_getattr =		ufs_getattr,
  2783		.vop_inactive =		ufs_inactive,
  2784		.vop_kqfilter =		ufsfifo_kqfilter,
  2785		.vop_markatime =	ufs_markatime,
  2786		.vop_pathconf = 	ufs_pathconf,
  2787		.vop_print =		ufs_print,
  2788		.vop_read =		VOP_PANIC,
  2789		.vop_reclaim =		ufs_reclaim,
  2790		.vop_setattr =		ufs_setattr,
  2791	#ifdef MAC
  2792		.vop_setlabel =		vop_stdsetlabel_ea,
  2793	#endif
  2794		.vop_write =		VOP_PANIC,
  2795	#ifdef UFS_EXTATTR
  2796		.vop_getextattr =	ufs_getextattr,
  2797		.vop_deleteextattr =	ufs_deleteextattr,
  2798		.vop_setextattr =	ufs_setextattr,
  2799	#endif
  2800	#ifdef UFS_ACL
  2801		.vop_getacl =		ufs_getacl,
  2802		.vop_setacl =		ufs_setacl,
  2803		.vop_aclcheck =		ufs_aclcheck,
  2804	#endif
  2805	};
