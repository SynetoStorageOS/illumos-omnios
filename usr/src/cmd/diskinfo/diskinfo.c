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
 * Copyright (c) 2013 Joyent Inc., All rights reserved.
 * Copyright (c) 2015 Syneto LTD., All rights reserved.
 */

#include <sys/types.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <ctype.h>
#include <stdarg.h>
#include <strings.h>

#include <libdiskmgt.h>
#include <sys/nvpair.h>

#include <fm/libtopo.h>
#include <fm/topo_hc.h>
#include <fm/topo_list.h>
#include <sys/fm/protocol.h>
#include <disk/disk.h>
#include <stdlib.h>

#include <config_admin.h>
#include <sys/param.h>

#include<fcntl.h>
#include<sys/ioctl.h>
#include<sys/dkio.h>


#include "diskname_converter.h"
#include "kstats.h"

typedef struct di_opts {
	boolean_t di_scripted;
	boolean_t di_parseable;
	boolean_t di_physical;
	boolean_t di_condensed;
	boolean_t di_json;
} di_opts_t;

typedef struct di_phys {
	char *dp_device;
	char *dp_serialnumber;
	char *dp_slotname;
	char *dp_chassis;
	int dp_slotnumber;
	int dp_faulty;
	int dp_identifying;
} di_phys_t;

static void __NORETURN
		fatal(int rv, const char *fmt, ...) {
	va_list ap;

	va_start(ap, fmt);
	(void) vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(rv);
}

static void usage(const char *execname) {
	(void) fprintf(stderr, "Usage: %s [-Hp] [{-c|-P}]\n", execname);
}

static void nvlist_query_string(nvlist_t *nvl, const char *label, char **val) {
	if (nvlist_lookup_string(nvl, label, val) != 0)
		*val = "-";
}

static const char *
display_string(const char *label) {
	return ((label) ? label : "-");
}

static const char *
display_tristate(int val) {
	if (val == 0)
		return ("no");
	if (val == 1)
		return ("yes");

	return ("-");
}

static char condensed_tristate(int val, char c) {
	if (val == 0)
		return ('-');
	if (val == 1)
		return (c);

	return ('?');
}


static void populate_serial_numbers(di_phys_t *phys) {
	disk_list_t *dlist = lookup_dsk_name(phys->dp_device);

	if (dlist) {
		if (phys->dp_serialnumber == NULL) {
			phys->dp_serialnumber = strdup(getSerialNumber(dlist->ks_name));
		}
	}
}

static void populate_internal_disk_topology(di_phys_t *phys) {
	int chassis = -1;
	int slot = -1;

	if (phys->dp_chassis != NULL)
		return;

	asprintf(&phys->dp_chassis, "-");
	if (sscanf(phys->dp_device, "c%dt%dd0", &chassis, &slot) > 0) {
		phys->dp_slotnumber = slot;
		asprintf(&phys->dp_slotname, "Internal Disk %d", slot);
	} else {
		phys->dp_slotnumber = -1;
		asprintf(&phys->dp_slotname, "-");
	}
}

static int disk_walker(topo_hdl_t *hp, tnode_t *np, void *arg) {
	di_phys_t *pp = arg;
	tnode_t *pnp;
	tnode_t *ppnp;
	topo_faclist_t fl;
	topo_faclist_t *lp;
	int err;
	topo_led_state_t mode;
	topo_led_type_t type;
	char *name, *slotname, *serial;

	if (strcmp(topo_node_name(np), DISK) != 0)
		return (TOPO_WALK_NEXT);

	if (topo_prop_get_string(np, TOPO_PGROUP_STORAGE,
							 TOPO_STORAGE_LOGICAL_DISK_NAME, &name, &err) != 0) {
		return (TOPO_WALK_NEXT);
	}

	if (strcmp(name, pp->dp_device) != 0)
		return (TOPO_WALK_NEXT);

	if (topo_prop_get_string(np, TOPO_PGROUP_STORAGE,
							 TOPO_STORAGE_SERIAL_NUM, &serial, &err) == 0) {
		pp->dp_serialnumber = serial;
	}

	pnp = topo_node_parent(np);
	ppnp = topo_node_parent(pnp);
	if (strcmp(topo_node_name(pnp), BAY) == 0) {
		if (topo_node_facility(hp, pnp, TOPO_FAC_TYPE_INDICATOR, TOPO_FAC_TYPE_ANY, &fl, &err) == 0) {
			for (lp = topo_list_next(&fl.tf_list); lp != NULL; lp = topo_list_next(lp)) {
				if (topo_prop_get_uint32(lp->tf_node, TOPO_PGROUP_FACILITY, TOPO_FACILITY_TYPE, (uint32_t *) &type,
										 &err) != 0) {
					continue;
				}
				if (topo_prop_get_uint32(lp->tf_node, TOPO_PGROUP_FACILITY, TOPO_LED_MODE, (uint32_t *) &mode, &err)
					!= 0) {
					continue;
				}

				switch (type) {
					case TOPO_LED_TYPE_SERVICE:
						pp->dp_faulty |= mode;
						break;
					case TOPO_LED_TYPE_LOCATE:
						pp->dp_identifying |= mode;
						break;
					default:
						break;
				}
			}
		}

		if (topo_prop_get_string(pnp, TOPO_PGROUP_PROTOCOL, TOPO_PROP_LABEL, &slotname, &err) == 0) {
			pp->dp_slotname = slotname;
		}

		pp->dp_slotnumber = topo_node_instance(pnp);
	}

	char *new_dp_chassis;
	if (pp->dp_chassis == NULL) {
		asprintf(&new_dp_chassis, "%d", topo_node_instance(ppnp));
	} else {
		asprintf(&new_dp_chassis, "%s:%d", pp->dp_chassis, topo_node_instance(ppnp));
	}
	if (pp->dp_chassis) {
		free(pp->dp_chassis);
	}
	pp->dp_chassis = new_dp_chassis;

	return (TOPO_WALK_TERMINATE);
}

static void populate_physical(topo_hdl_t *hp, di_phys_t *pp) {
	int err;
	topo_walk_t *wp;

	pp->dp_faulty = pp->dp_identifying = 0;
	pp->dp_slotnumber = -1;

	err = 0;
	wp = topo_walk_init(hp, FM_FMRI_SCHEME_HC, disk_walker, pp, &err);
	if (wp == NULL) {
		fatal(-1, "unable to initialise topo walker: %s", topo_strerror(err));
	}

	while ((err = topo_walk_step(wp, TOPO_WALK_CHILD)) == TOPO_WALK_NEXT);

	if (err == TOPO_WALK_ERR)
		fatal(-1, "topo walk failed");

	topo_walk_fini(wp);

	populate_serial_numbers(pp);
	populate_internal_disk_topology(pp);
}

static void enumerate_disks(di_opts_t *opts) {
	topo_hdl_t *hp;
	dm_descriptor_t *media;
	int err, j, i;
	int filter[] = {DM_DT_FIXED, -1};
	dm_descriptor_t *disk, *controller;
	nvlist_t *mattrs, *dattrs, *cattrs = NULL;
	cfga_err_t p;
	cfga_list_data_t *lista;
	int nr;

	uint64_t size, total;
	uint32_t blocksize;
	double total_in_GiB;
	char sizestr[32];
	char slotname[32];
	char statestr[8];
	char sataname[8];

	char *vendor_id, *product_id, *full_device_path, *c, *connection_type = NULL;
	boolean_t is_removable;
	boolean_t is_ssd;
	char devicename[MAXPATHLEN];
	di_phys_t phys;
	size_t len;

	err = 0;
	if ((media = dm_get_descriptors(DM_MEDIA, filter, &err)) == NULL) {
		fatal(-1, "failed to obtain media descriptors: %s\n", strerror(err));
	}

	err = 0;
	hp = topo_open(TOPO_VERSION, NULL, &err);
	if (hp == NULL) {
		fatal(-1, "unable to obtain topo handle: %s", topo_strerror(err));
	}

	err = 0;
	(void) topo_snap_hold(hp, NULL, &err);
	if (err != 0) {
		fatal(-1, "unable to hold topo snapshot: %s", topo_strerror(err));
	}

	p = config_list_ext(0, NULL, &lista, &nr, NULL, NULL, NULL, CFGA_FLAG_LIST_ALL);
	if (opts->di_json) {
		printf("{\"disks\": {");
	}

	for (i = 0; media != NULL && media[i] != NULL; i++) {
		if ((disk = dm_get_associated_descriptors(media[i], DM_DRIVE, &err)) == NULL) {
			continue;
		}

		mattrs = dm_get_attributes(media[i], &err);
		err = nvlist_lookup_uint64(mattrs, DM_SIZE, &size);
		assert(err == 0);
		err = nvlist_lookup_uint32(mattrs, DM_BLOCKSIZE, &blocksize);
		assert(err == 0);
		nvlist_free(mattrs);

		dattrs = dm_get_attributes(disk[0], &err);

		nvlist_query_string(dattrs, DM_VENDOR_ID, &vendor_id);
		nvlist_query_string(dattrs, DM_PRODUCT_ID, &product_id);
		nvlist_query_string(dattrs, DM_OPATH, &full_device_path);

		is_removable = B_FALSE;
		if (nvlist_lookup_boolean(dattrs, DM_REMOVABLE) == 0)
			is_removable = B_TRUE;

		is_ssd = B_FALSE;

		if (nvlist_lookup_boolean(dattrs, DM_SOLIDSTATE) == 0)
			is_ssd = B_TRUE;

		if ((controller = dm_get_associated_descriptors(disk[0], DM_CONTROLLER, &err)) != NULL) {
			cattrs = dm_get_attributes(controller[0], &err);
			nvlist_query_string(cattrs, DM_CTYPE, &connection_type);
			connection_type = strdup(connection_type);
			for (c = connection_type; *c != '\0'; c++)
				*c = (char) toupper(*c);


		}

		//fd = open(full_device_path, O_RDONLY);
		//printf("%s, %d", full_device_path,fd);


		/*
		 * Parse full devicename path to only show the devicename name,
		 * i.e. c0t1d0.  Many paths will reference a particular
		 * slice (c0t1d0s0), so remove the slice if present.
		 */
		if ((c = strrchr(full_device_path, '/')) != NULL)
			(void) strlcpy(devicename, c + 1, sizeof(devicename));
		else
			(void) strlcpy(devicename, full_device_path, sizeof(devicename));
		len = strlen(devicename);

		if (devicename[len - 2] == 's' && (devicename[len - 1] >= '0' && devicename[len - 1] <= '9'))
			devicename[len - 2] = '\0';

		bzero(&phys, sizeof(phys));
		phys.dp_device = devicename;
		populate_physical(hp, &phys);

		/*
		 * The size is given in blocks, so multiply the number
		 * of blocks by the block size to get the total size,
		 * then convert to GiB.
		 */
		total = size * blocksize;

		if (opts->di_parseable || opts->di_json) {
			(void) snprintf(sizestr, sizeof(sizestr), "%lu", total);
		} else {
			total_in_GiB = (double) total / 1024.0 / 1024.0 / 1024.0;
			(void) snprintf(sizestr, sizeof(sizestr), "%7.2f GiB", total_in_GiB);
		}

		if (opts->di_parseable || opts->di_json) {
			for (j = 0; j < nr; j++)
				if (strstr(lista[j].ap_log_id, phys.dp_device) != NULL && strstr(lista[j].ap_class, "sata") != NULL) {
					(void) snprintf(slotname, sizeof(slotname), "sata%c,%d", lista[j].ap_log_id[4], phys.dp_slotnumber);
					(void) snprintf(sataname, sizeof(sataname), "sata%c", lista[j].ap_log_id[4]);
					break;
				}
			if (j >= nr) {
				(void) snprintf(slotname, sizeof(slotname), "%s,%d", phys.dp_chassis, phys.dp_slotnumber);
			}

		} else if (phys.dp_slotname != NULL) {
			(void) snprintf(slotname, sizeof(slotname), "[%s] %s", phys.dp_chassis, phys.dp_slotname);
		} else {
			slotname[0] = '-';
			slotname[1] = '\0';
		}

		if (opts->di_condensed) {
			(void) snprintf(statestr, sizeof(statestr), "%c%c%c%c", condensed_tristate(phys.dp_faulty, 'F'),
							condensed_tristate(phys.dp_identifying, 'L'), condensed_tristate(is_removable, 'R'),
							condensed_tristate(is_ssd, 'S'));
		}

		if (opts->di_json) {
			(void) snprintf(statestr, sizeof(statestr), "%c%c%c%c", condensed_tristate(phys.dp_faulty, 'F'),
							condensed_tristate(phys.dp_identifying, 'L'), condensed_tristate(is_removable, 'R'),
							condensed_tristate(is_ssd, 'S'));
			if (i > 0)
				printf(",");

			printf("\"%s\":{"
						   "\"connectionType\":\"%s\","
						   "\"deviceName\":\"%s\","
						   "\"vendorId\":\"%s\","
						   "\"productId\":\"%s\","
						   "\"serialNumber\":\"%s\","
						   "\"size\":%llu,"
						   "\"state\":"
							   "{\"isFaulty\":%s,"
							   "\"isIdentifying\":%s,"
							   "\"isRemovable\": %s,"
							   "\"isSsd\": %s,"
							   "\"hardErrors\": %ld,"
							   "\"softErrors\": %ld,"
							   "\"transportErrors\": %ld"
							   "},"
						   "\"slot\":"
							   "{"
							   "\"chassis\": \"%s\","
							   "\"name\":\"%s\","
							   "\"number\":%d"
							   "}"
						   "}", devicename,
				   connection_type, devicename, vendor_id, product_id,
				   display_string(phys.dp_serialnumber), total, phys.dp_faulty ? "true" : "false", phys.dp_identifying ? "true" : "false",
				   is_removable ? "true" : "false", is_ssd ? "true" : "false",
				   get_error_counter_by_serial_number((phys.dp_serialnumber == NULL) ? "" : phys.dp_serialnumber,
													  "Hard Errors"),
				   get_error_counter_by_serial_number((phys.dp_serialnumber == NULL) ? "" : phys.dp_serialnumber,
													  "Soft Errors"),
				   get_error_counter_by_serial_number((phys.dp_serialnumber == NULL) ? "" : phys.dp_serialnumber,
													  "Transport Errors"),
				   strlen(sataname) == 0 ? phys.dp_chassis : sataname, phys.dp_slotname, phys.dp_slotnumber);


		}

		else if (opts->di_parseable) {
			(void) snprintf(statestr, sizeof(statestr), "%c%c%c%c", condensed_tristate(phys.dp_faulty, 'F'),
							condensed_tristate(phys.dp_identifying, 'L'), condensed_tristate(is_removable, 'R'),
							condensed_tristate(is_ssd, 'S'));

			printf("%s;%s;%s;%s;%s;%llu;%s;%s;%s;%s;%s;%s;%ld;%ld;%ld\n", connection_type, devicename, vendor_id,
				   product_id,
				   display_string(phys.dp_serialnumber), total, statestr, slotname,
				   display_tristate(is_removable), display_tristate(is_ssd),
				   display_tristate(phys.dp_faulty), display_tristate(phys.dp_identifying),
				   get_error_counter_by_serial_number((phys.dp_serialnumber == NULL) ? "" : phys.dp_serialnumber,
													  "Soft Errors"),
				   get_error_counter_by_serial_number((phys.dp_serialnumber == NULL) ? "" : phys.dp_serialnumber,
													  "Hard Errors"),
				   get_error_counter_by_serial_number((phys.dp_serialnumber == NULL) ? "" : phys.dp_serialnumber,
													  "Transport Errors")
			);
		} else if (opts->di_physical) {
			if (!opts->di_scripted) {
				printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", devicename, vendor_id, product_id,
					   display_string(phys.dp_serialnumber),
					   display_tristate(phys.dp_faulty), display_tristate(phys.dp_identifying),
					   slotname);
			} else {
				printf("%-22s  %-8s %-16s "
							   "%-20s %-3s %-3s %s\n", devicename, vendor_id, product_id,
					   display_string(phys.dp_serialnumber), display_tristate(phys.dp_faulty),
					   display_tristate(phys.dp_identifying), slotname);
			}
		} else if (opts->di_condensed) {
			if (!opts->di_scripted) {
				printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n", connection_type, devicename, vendor_id, product_id,
					   display_string(phys.dp_serialnumber), sizestr, statestr, slotname);
			} else {
				printf("%-7s %-22s  %-8s %-16s "
							   "%-20s\n\t%-13s %-4s %s\n", connection_type, devicename, vendor_id, product_id,
					   display_string(phys.dp_serialnumber), sizestr, statestr, slotname);
			}
		} else {
			if (!opts->di_scripted) {
				printf("%s\t%s\t%s\t%s\t%s\t%s\t%s\n", connection_type, devicename, vendor_id, product_id, sizestr,
					   display_tristate(is_removable), display_tristate(is_ssd));
			} else {
				printf("%-7s %-22s  %-8s %-16s "
							   "%-13s %-3s %-3s\n", connection_type, devicename, vendor_id, product_id, sizestr,
					   display_tristate(is_removable), display_tristate(is_ssd));
			}
		}

		free(connection_type);
		nvlist_free(cattrs);
		nvlist_free(dattrs);
		dm_free_descriptors(controller);
		dm_free_descriptors(disk);
	}
	if (opts->di_json) {
		printf("}}");
		printf("\n");
	}
	free(lista);
	dm_free_descriptors(media);
	topo_snap_release(hp);
	topo_close(hp);
}

int main(int argc, char *argv[]) {
	char c;

	di_opts_t opts = {.di_condensed = B_FALSE, .di_scripted = B_TRUE, .di_physical = B_FALSE, .di_parseable = B_FALSE, .di_json = B_FALSE};

	while ((c = (char) getopt(argc, argv, ":cHPpJ")) != EOF) {
		switch (c) {
			case 'c':
				if (opts.di_physical) {
					usage(argv[0]);
					fatal(1, "-c and -P are mutually exclusive\n");
				}
				opts.di_condensed = B_TRUE;
				break;
			case 'H':
				opts.di_scripted = B_FALSE;
				break;
			case 'P':
				if (opts.di_condensed) {
					usage(argv[0]);
					fatal(1, "-c and -P are mutually exclusive\n");
				}
				opts.di_physical = B_TRUE;
				break;
			case 'p':
				opts.di_parseable = B_TRUE;
				break;
			case 'J':
				opts.di_json = B_TRUE;
				break;

			case '?':
				usage(argv[0]);
				fatal(1, "unknown option -%c\n", optopt);
			default:
				fatal(-1, "unexpected error on option -%c\n", optopt);
		}
	}

	if (!opts.di_scripted) {
		if (opts.di_physical) {
			printf("DISK                    VID      PID"
						   "              SERIAL               FLT LOC"
						   " LOCATION\n");
		} else if (opts.di_condensed) {
			printf("TYPE    DISK                    VID      PID"
						   "              SERIAL\n");
			printf("\tSIZE          FLRS LOCATION\n");
		} else {
			printf("TYPE    DISK                    VID      PID"
						   "              SIZE          RMV SSD\n");
		}
	}

	enumerate_disks(&opts);

	return (0);
}
