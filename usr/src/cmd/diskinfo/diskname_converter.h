/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2015 Syneto LTD., All rights reserved.
 */

#ifndef __DISKNAME_CONVERTER_H__
#define __DISKNAME_CONVERTER_H__

/*
 * Description of each device identified
 */
typedef struct list_of_disks {
	char *ks_name;
	/* untranslated kstat name */
	char *dsk;
	/* in form of cNtNdN */
	char *dname;
	/* in form of /dev/dsk/cNtNdN */
	char *devidstr;
	/* in form of "id1,sd@XXXX" */
	struct list_of_disks *next;        /* link to next one */
} disk_list_t;

/* disk/tape/misc info */
typedef struct {
	char *minor_name;
	int minor_isdisk;
} minor_match_t;

void *safe_alloc(size_t size);
char *safe_strdup(char *str);

char *mdsetno2name(int setno);
int drvinstunitpart2dev(char *driver, int instunit, char *part, char **devpathp, char **adevpathp, char **devidp);
int drvpid2port(uint_t pid, char **target_portp);
disk_list_t *lookup_ks_name(char *ks_name, int want_devid);
disk_list_t *lookup_dsk_name(const char *dsk_name);

#endif // __DISKNAME_CONVERTER_H__
