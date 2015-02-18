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

#include <kstat.h>

#ifndef __DISKINFO_KSTATS_C__
#define __DISKINFO_KSTATS_C__

#define MAX_KSTAT_SDS 65535

long get_error_counter_by_serial_number(char const *serial, char *error_counter_name);
char *getSerialNumber(const char *ks_name);
char *getKStatString(kstat_ctl_t *kernelDesc, char *moduleName, char *recordName, char *fieldName);
long getKStatNumber(kstat_ctl_t *kernelDesc, char *moduleName, char *recordName, char *fieldName);

#endif // __DISKINFO_KSTATS_C__
