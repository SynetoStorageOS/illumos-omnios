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

#include <stdio.h>
#include <strings.h>

#include "kstats.h"

long get_error_counter_by_serial_number(char const *serial, char *error_counter_name) {
	kstat_ctl_t *ks_ctl;
	char *kstat_sds[MAX_KSTAT_SDS];
	char *kstat_serial;
	int kstat_sd_instance = 0;
	int i = 0;

	if (strlen(serial) == 0) {
		return -1;
	}

	kstat_t *ks_p;
	ks_ctl = kstat_open();
	for (ks_p = ks_ctl->kc_chain; ks_p != NULL; ks_p = ks_p->ks_next) {
		if (strstr(ks_p->ks_name, "sd") && strstr(ks_p->ks_name, ",err")) {
			kstat_sds[kstat_sd_instance++] = ks_p->ks_name;
		}
	}

	for (i = 0; i < kstat_sd_instance; i++) {
		kstat_serial = getKStatString(ks_ctl, "sderr", kstat_sds[i], "Serial No");
		if (kstat_serial != NULL && strcmp(kstat_serial, serial)) {
			kstat_close(ks_ctl);
			return getKStatNumber(ks_ctl, "sderr", kstat_sds[i], error_counter_name);
		}
	}
	kstat_close(ks_ctl);
	return -1;
}

char *
getSerialNumber(const char *ks_name) {
	kstat_ctl_t *ks_ctl;
	char *ks_name_err;
	char *serial;

	asprintf(&ks_name_err, "%s,err", ks_name);

	ks_ctl = kstat_open();
	serial = getKStatString(ks_ctl, "sderr", ks_name_err, "Serial No");
	kstat_close(ks_ctl);

	return serial;
}

/* Fetch numerical statistic from kernel */
long getKStatNumber(kstat_ctl_t *kernelDesc, char *moduleName,
    char *recordName, char *fieldName) {
	kstat_t *kstatRecordPtr;
	kstat_named_t *kstatFields;
	long value;
	int i;

	if ((kstatRecordPtr = kstat_lookup(kernelDesc, moduleName, -1, recordName)) ==
	    NULL) {
		return (-1);
	}

	if (kstat_read(kernelDesc, kstatRecordPtr, NULL) < 0)
		return (-1);

	kstatFields = KSTAT_NAMED_PTR(kstatRecordPtr);

	for (i = 0; i < kstatRecordPtr->ks_ndata; i++) {
		if (strcmp(kstatFields[i].name, fieldName) == 0) {
			switch (kstatFields[i].data_type) {
				case KSTAT_DATA_INT32:
					value = kstatFields[i].value.i32;
					break;
				case KSTAT_DATA_UINT32:
					value = kstatFields[i].value.ui32;
					break;
				case KSTAT_DATA_INT64:
					value = kstatFields[i].value.i64;
					break;
				case KSTAT_DATA_UINT64:
					value = kstatFields[i].value.ui64;
					break;
				default:
					value = -1;
			}
			return (value);
		}
	}
	return (-1);
}

/* Fetch string statistic from kernel */
char *getKStatString(kstat_ctl_t *kernelDesc, char *moduleName,
    char *recordName, char *fieldName) {
	kstat_t *kstatRecordPtr;
	kstat_named_t *kstatFields;
	char *value;
	int i;

	if ((kstatRecordPtr = kstat_lookup(kernelDesc, moduleName, -1, recordName)) ==
	    NULL) {
		return (NULL);
	}

	if (kstat_read(kernelDesc, kstatRecordPtr, NULL) < 0)
		return (NULL);

	kstatFields = KSTAT_NAMED_PTR(kstatRecordPtr);

	for (i = 0; i < kstatRecordPtr->ks_ndata; i++) {
		if (strcmp(kstatFields[i].name, fieldName) == 0) {
			switch (kstatFields[i].data_type) {
				case KSTAT_DATA_CHAR:
					value = kstatFields[i].value.c;
					break;
				default:
					value = NULL;
			}
			return (value);
		}
	}
	return (NULL);
}
