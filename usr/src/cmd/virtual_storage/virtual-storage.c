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
/*
 * The Syneto VirtualStorage OCF resource represented by the
 * triplet (ethernet_interface, ip_address, zpool).
 */

#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libzfs.h>
#include <sys/zio.h>
#include <sys/fs/zfs.h>
#include <kstat.h>
#include <syslog.h>

#define START_CMD       "start"
#define STOP_CMD        "stop"
#define STATUS_CMD 	"status"
#define MONITOR_CMD     "monitor"
#define ADVT_CMD        "advt"
#define RECOVER_CMD     "recover"
#define RELOAD_CMD      "reload"
#define META_DATA_CMD   "meta-data"
#define VALIDATE_CMD    "validate-all"

#define OCF_SUCCESS            0
#define OCF_ERR_GENERIC        1
#define OCF_ERR_ARGS           2
#define OCF_ERR_UNIMPLEMENTED  3
#define OCF_ERR_PERM           4
#define OCF_ERR_INSTALLED      5
#define OCF_ERR_CONFIGURED     6
#define OCF_NOT_RUNNING        7
#define OCF_RUNNING_MASTER     8
#define OCF_FAILED_MASTER      9

#define OCF_RESKEY_SIZE 1024

#define PHP_BINARY "php"

#define SYSLOG_IDENT "HA"
#define log_debug(...) syslog(LOG_DEBUG, __VA_ARGS__)
#define log_info(...) syslog(LOG_INFO, __VA_ARGS__)
#define log_error(...) syslog(LOG_ERR, __VA_ARGS__)

extern int errno;


/*
 * We check link state (up or down) by reading the
 * 'link::<interface_name>:link_state' kstat value.
 */
boolean_t isLinkFailed(char *OCF_RESKEY_interface_name) {
	kstat_ctl_t *kernelDesc;
	kstat_t *kstatRecordPtr;
	kstat_named_t *kstatFields;
	long link_state = -1;
	int i;

	if (OCF_RESKEY_interface_name == NULL) {
		log_error("ERROR: You must set OCF_RESKEY_interface_name"
		    " environment evariable to ethernet interface name.");
		return B_TRUE;
	}

	kernelDesc = kstat_open();

	if ((kstatRecordPtr = kstat_lookup(kernelDesc, "link", -1, OCF_RESKEY_interface_name)) == NULL) {
		return B_TRUE;
	}

	if (kstat_read(kernelDesc, kstatRecordPtr, NULL) < 0) {
		kstat_close(kernelDesc);
		return B_TRUE;
	}

	kstatFields = KSTAT_NAMED_PTR(kstatRecordPtr);

	for (i = 0; i < kstatRecordPtr->ks_ndata; i++) {
		if (strcmp(kstatFields[i].name, "link_state") == 0) {
			switch (kstatFields[i].data_type) {
				case KSTAT_DATA_INT32:
					link_state = kstatFields[i].value.i32;
					break;
				case KSTAT_DATA_UINT32:
					link_state = kstatFields[i].value.ui32;
					break;
				case KSTAT_DATA_INT64:
					link_state = kstatFields[i].value.i64;
					break;
				case KSTAT_DATA_UINT64:
					link_state = kstatFields[i].value.ui64;
					break;
				default:
					link_state = -1;
			}
			break;
		}
	}
	kstat_close(kernelDesc);

	if (link_state == 1)
		return B_FALSE;

	log_error("ERROR: Link state for interface %s is %d", OCF_RESKEY_interface_name, link_state);
	return B_TRUE;
}


/*
 * We check that the IP address is configured on this system. It does not
 * matter on which interface it is configured (for the purpose of this check).
 *
 * We check if the IP address is configured (live and in-kernel) by searching
 * for it in the list returned by getifaddrs(3SOCKET).
 *
 * No need to check for netmask, as if an IP is up, it can be up with any
 * netmask to be good enough for this check. As OCF_RESKEY_net_address can be
 * in CIDR notation, we have to compare the IP address up to first '/' char or
 * to the end of the OCF_RESKEY_net_address string.
 */
boolean_t isIpConfigured(char *OCF_RESKEY_net_address) {
	struct ifaddrs *interface_list, *interface;
	int interface_address_len = INET_ADDRSTRLEN;
	char interface_address[INET_ADDRSTRLEN];

	if (OCF_RESKEY_net_address == NULL) {
		log_error(
		    "ERROR: You must set OCF_RESKEY_net_address environment"
			"variable to checked\nethernet interface IPv4 address."
		);
		return B_FALSE;
	}

	if (getifaddrs(&interface_list)) {
		log_error("ERROR: Cannot get interface addresses from kernel (%s)", strerror(errno));
		return B_FALSE;
	}

	int i = 0;
	for (interface = interface_list; interface; interface = interface->ifa_next) {
		int address_family = interface->ifa_addr->sa_family;
		const void *address;

		switch (address_family) {
			case AF_INET:
				address = &((struct sockaddr_in *) interface->ifa_addr)->sin_addr;
				break;
			default:
				address = NULL;
		}

		if (address != NULL) {
			if (inet_ntop(address_family, address, interface_address, sizeof interface_address) == NULL) {
				continue;
			}
			if (strrchr(OCF_RESKEY_net_address, '/'))
				interface_address_len = (int) (strrchr(OCF_RESKEY_net_address, '/') - OCF_RESKEY_net_address);
			if (strncmp(interface_address, OCF_RESKEY_net_address, interface_address_len) == 0) {
				return B_TRUE;
			}

		}
	}

	freeifaddrs(interface_list);

	log_error("ERROR: Cannot find any interface with this IP address: %s", OCF_RESKEY_net_address);
	return B_FALSE;
}


/* Check that pool is failed by opening a zpool handle and checking that pool
 * state is ACTIVE.
 *
 * We could also check if IO is suspended, but in HA we always have
 * failmode=panic, so it is useless.
 *
 * If we have multiple pools and one loses redundancy we're panicked, all
 * the healthy pools will move to the other node. This sucks, but we cannot try
 * to import pool on the other node as we're not guaranteed that the pool that
 * lost redundancy right now will not wake up later and damage our data.
 *
 * This means that a POOL_STATE_ACTIVE on a zpool_handle_t we successfully
 * opened (with failmode=panic) is enough to tell us that the pool is really
 * present and usable.
 */
boolean_t isPoolFailed(const char *OCF_RESKEY_pool) {
	libzfs_handle_t *lzhp;
	zpool_handle_t *zhp;
	nvlist_t *pool_config;
	uint64_t suspended;

	if (OCF_RESKEY_pool == NULL) {
		log_error("ERROR: You must set OCF_RESKEY_pool environment variable to zpool name");
		return B_TRUE;
	}

	if ((lzhp = libzfs_init()) == NULL) {
		log_error("ERROR: Cannot open libzfs handle");
		return B_TRUE;
	}
	if ((zhp = zpool_open(lzhp, OCF_RESKEY_pool)) == NULL) {
		log_error("ERROR: Cannot open zpool handle for pool %s", OCF_RESKEY_pool);
		return B_TRUE;
	};

	if (zpool_get_state(zhp) != POOL_STATE_ACTIVE) {
		log_error("ERROR: Pool is not in active state (state is %d).", zpool_get_state(zhp));
		return B_TRUE;
	}

	zpool_close(zhp);
	libzfs_fini(lzhp);

	return B_FALSE;
}


int monitor() {
	char *const OCF_RESKEY_interface_name = getenv("OCF_RESKEY_interface_name");
	char *const OCF_RESKEY_net_address = getenv("OCF_RESKEY_net_address");
	char *const OCF_RESKEY_pool = getenv("OCF_RESKEY_pool");

	if (isLinkFailed(OCF_RESKEY_interface_name))
		return OCF_NOT_RUNNING;

	if (!isIpConfigured(OCF_RESKEY_net_address))
		return OCF_NOT_RUNNING;

	if (isPoolFailed(OCF_RESKEY_pool))
		return OCF_NOT_RUNNING;

	log_info("INFO: 'virtual-storage monitor' returned OCF_SUCCESS");
	return OCF_SUCCESS;
}

int runPhpCode(const char *php_code)
{
	FILE *interpreter_handle;
	interpreter_handle = popen(PHP_BINARY, "w");
	if (interpreter_handle == NULL) {
		log_error("ERROR: Cannot run php interpreter (%s)", strerror(errno));
		return OCF_ERR_GENERIC;
	}
	fprintf(interpreter_handle, "%s", php_code);
	return pclose(interpreter_handle);
}

#define COMMON_PHP_CODE "<?php require_once 'Lego/autoload.php';                                                                     "\
"	$agent = new HA_ResourceAgents_VirtualStorage_OCFAgent(                                                                      "\
"		new HA_ResourceAgents_VirtualStorage_Pool(getenv('OCF_RESKEY_pool')),                                                "\
"	        new HA_ResourceAgents_VirtualStorage_Network(getenv('OCF_RESKEY_interface_name'), getenv('OCF_RESKEY_net_address')   "\
"	));                                                                                                                          "\
"       $agent->"

int start() {
	return runPhpCode(COMMON_PHP_CODE "start();");
}

int stop() {
	return runPhpCode(COMMON_PHP_CODE "stop();");
}

int metadata() {
	const char *meta_data =
	"<?xml version=\"1.0\"?>\n"
	"<!DOCTYPE resource-agent SYSTEM \"ra-api-1.dtd\">\n"
	"    <resource-agent name=\"VirtualStorage\" version=\"1.0\">\n"
	"    <version>1.0</version>\n"
	"    <parameters>\n"
	"    <parameter name=\"pool\" required=\"1\" unique=\"1\">\n"
	"    <longdesc lang=\"en\">\n"
	"    The name of the zfs pool managed by this Virtual Storage. This is the zfs pool that will be imported\n"
	"on each migration.\n"
	"\n"
	"    This parameter cannot be left empty and is also unique amongst all virtual storage resources.\n"
	"    </longdesc>\n"
	"    <shortdesc lang=\"en\">Name of the zfs zpool</shortdesc>\n"
	"    <content type=\"string\"/>\n"
	"    </parameter>\n"
	"    <parameter name=\"interface_name\">\n"
	"    <longdesc lang=\"en\">\n"
	"The name of the physical interface on top of which the vnic will be created to host\n"
	"the Virtual Storage ip.\n"
	"\n"
	"    This parameter can be left empty. If its empty the Virtual Storage resource will assume that\n"
	"the access to the data present on the pool will be done using fiber channel.\n"
	"    </longdesc>\n"
	"    <shortdesc lang=\"en\">Name of the network interface that will host the Virtual Storage ip.</shortdesc>\n"
	"    <content type=\"string\"/>\n"
	"    </parameter>\n"
	"    <parameter name=\"net_address\">\n"
	"    <longdesc lang=\"en\">\n"
	"    The network address used by external clients to access the data shared from\n"
	"the zfs pool.\n"
	"\n"
	"    This parameter can be left empty. If its empty the Virtual Storage resource will assume that\n"
	"the access to the data present on the pool will be done using fiber channel.\n"
	"    </longdesc>\n"
	"    <shortdesc lang=\"en\">Network address used to access the data on the zfs pool.</shortdesc>\n"
	"    <content type=\"string\"/>\n"
	"    </parameter>\n"
	"    </parameters>\n"
	"    <actions>\n"
	"    <action name=\"start\" timeout=\"300\" interval=\"0\"/>\n"
	"    <action name=\"stop\" timeout=\"300\" interval=\"0\"/>\n"
	"    <action name=\"monitor\" timeout=\"30\" interval=\"10\"/>\n"
	"    <action name=\"meta-data\" timeout=\"5\"/>\n"
	"    </actions>\n"
	"    </resource-agent>\n";
	printf("%s\n", meta_data);
	return OCF_SUCCESS;
}

void exit_usage(const char *self) {
	fprintf(stderr, "usage: %s {start|stop|monitor|meta-data}\n", self);
	log_error("ERROR: %s called with incorrect parameters", self);
	closelog();
	exit(OCF_ERR_ARGS);
}


int main(int argc, char *argv[]) {
	openlog(SYSLOG_IDENT, LOG_PID, LOG_USER);

	if (argv[1] == NULL)
		exit_usage(argv[0]);

	if (0 == strncmp(START_CMD,argv[1], strlen(START_CMD)))
		return(start());
	if (0 == strncmp(STOP_CMD,argv[1], strlen(STOP_CMD)))
		return(stop());
	if (0 == strncmp(MONITOR_CMD,argv[1], strlen(MONITOR_CMD)))
		return(monitor());
	if (0 == strncmp(META_DATA_CMD,argv[1], strlen(META_DATA_CMD)))
		return(metadata());

	exit_usage(argv[0]);

#pragma notreached
	return OCF_ERR_ARGS;
}
