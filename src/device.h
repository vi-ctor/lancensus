/* SPDX-License-Identifier: MIT */
/* Portable device table + protocol parsers (no Linux/BPF dependencies). */
#ifndef LANCENSUS_DEVICE_H
#define LANCENSUS_DEVICE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>

#define LC_MAX_IPS   4
#define LC_MAX_SVCS  12
#define LC_STR       96
#define LC_SVC_STR   64

struct lc_device {
	uint8_t  mac[6];
	uint16_t vlan;
	char     ips[LC_MAX_IPS][46];
	int      n_ips;
	char     hostname[LC_STR];
	char     name[LC_STR];        /* friendly name (mDNS instance)       */
	char     model[LC_STR];       /* TXT ty= / usb_MDL= / product=      */
	char     ssdp_server[LC_STR]; /* SSDP SERVER or USER-AGENT           */
	char     dhcp_vendor[LC_STR]; /* DHCP option 60                      */
	char     dhcp_fp[LC_STR];     /* DHCP option 55, e.g. "1,3,6,15"     */
	char     services[LC_MAX_SVCS][LC_SVC_STR];
	int      n_svcs;
	time_t   first_seen, last_seen;
};

struct lc_table {
	struct lc_device *devs;
	size_t cap, n;
	FILE  *out;                   /* JSON lines on change; NULL = silent */
};

int  lc_table_init(struct lc_table *t, size_t cap, FILE *out);
void lc_table_free(struct lc_table *t);

/* Feed one captured UDP payload. ip is the source address as text.
 * Returns 1 if a device record was created or changed, 0 otherwise. */
int  lc_feed(struct lc_table *t, const uint8_t mac[6], uint16_t vlan,
	     const char *ip, uint16_t sport, uint16_t dport,
	     const uint8_t *payload, size_t len);

const struct lc_device *lc_find(const struct lc_table *t,
				const uint8_t mac[6], uint16_t vlan);
int  lc_has_service(const struct lc_device *d, const char *svc);
void lc_print_summary(const struct lc_table *t, FILE *f);

#endif
