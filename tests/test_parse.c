// SPDX-License-Identifier: MIT
/* Parser tests: known-good samples plus truncation/mutation robustness.
 * Portable (Linux/macOS); run under -fsanitize=address,undefined. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "device.h"

static int failures;

#define CHECK(cond) do { \
	if (!(cond)) { fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); failures++; } \
} while (0)

static uint8_t *load(const char *dir, const char *name, size_t *len)
{
	char path[512];
	FILE *f;
	uint8_t *buf;
	long n;

	snprintf(path, sizeof(path), "%s/%s", dir, name);
	f = fopen(path, "rb");
	if (!f) {
		perror(path);
		exit(2);
	}
	fseek(f, 0, SEEK_END);
	n = ftell(f);
	fseek(f, 0, SEEK_SET);
	buf = malloc((size_t)n);
	if (!buf || fread(buf, 1, (size_t)n, f) != (size_t)n)
		exit(2);
	fclose(f);
	*len = (size_t)n;
	return buf;
}

static int has_ip(const struct lc_device *d, const char *ip)
{
	for (int i = 0; i < d->n_ips; i++)
		if (strcmp(d->ips[i], ip) == 0)
			return 1;
	return 0;
}

static const uint8_t MAC_PRINTER[6] = { 0x02, 0, 0, 0, 0, 0x02 };
static const uint8_t MAC_SCANNER[6] = { 0x02, 0, 0, 0, 0, 0x03 };
static const uint8_t MAC_RELAY[6]   = { 0x02, 0, 0, 0, 0, 0x99 };
static const uint8_t MAC_CAMERA[6]  = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01 };

static void test_samples(const char *dir)
{
	struct lc_table t;
	const struct lc_device *d;
	uint8_t *p;
	size_t n;

	lc_table_init(&t, 16, NULL);

	p = load(dir, "mdns_printer.bin", &n);
	CHECK(lc_feed(&t, MAC_PRINTER, 0, "10.77.0.2", 5353, 5353, p, n) == 1);
	CHECK(lc_feed(&t, MAC_PRINTER, 0, "10.77.0.2", 5353, 5353, p, n) == 0); /* idempotent */
	free(p);
	d = lc_find(&t, MAC_PRINTER, 0);
	CHECK(d != NULL);
	if (d) {
		CHECK(strcmp(d->hostname, "office-printer") == 0);
		CHECK(strcmp(d->name, "Office Printer") == 0);
		CHECK(strcmp(d->model, "ExampleCo P400") == 0);
		CHECK(lc_has_service(d, "_ipp._tcp"));
		CHECK(has_ip(d, "10.77.0.2"));
	}

	p = load(dir, "ssdp_notify.bin", &n);
	CHECK(lc_feed(&t, MAC_PRINTER, 0, "10.77.0.2", 1900, 1900, p, n) == 1);
	free(p);
	d = lc_find(&t, MAC_PRINTER, 0);
	if (d) {
		CHECK(strcmp(d->ssdp_server, "Linux/5.10 UPnP/1.0 ExamplePrint/1.0") == 0);
		CHECK(lc_has_service(d, "urn:schemas-upnp-org:device:Printer:1"));
	}

	p = load(dir, "mdns_scanner.bin", &n);
	CHECK(lc_feed(&t, MAC_SCANNER, 0, "10.77.0.3", 5353, 5353, p, n) == 1);
	free(p);
	d = lc_find(&t, MAC_SCANNER, 0);
	CHECK(d != NULL);
	if (d) {
		CHECK(strcmp(d->name, "Lab Scanner") == 0);
		CHECK(strcmp(d->model, "ExampleCo S200") == 0);
		CHECK(lc_has_service(d, "_uscan._tcp"));
	}

	/* DHCP keys on chaddr, not the L2 source (relay case). */
	p = load(dir, "dhcp_discover.bin", &n);
	CHECK(lc_feed(&t, MAC_RELAY, 0, "0.0.0.0", 68, 67, p, n) == 1);
	free(p);
	CHECK(lc_find(&t, MAC_RELAY, 0) == NULL);
	d = lc_find(&t, MAC_CAMERA, 0);
	CHECK(d != NULL);
	if (d) {
		CHECK(strcmp(d->hostname, "ipcam-01") == 0);
		CHECK(strcmp(d->dhcp_vendor, "udhcp 1.36.1") == 0);
		CHECK(strcmp(d->dhcp_fp, "1,3,6,12,15,28,42") == 0);
		CHECK(has_ip(d, "10.77.0.50"));
	}

	/* Same MAC on another VLAN is a different device. */
	p = load(dir, "mdns_printer.bin", &n);
	CHECK(lc_feed(&t, MAC_PRINTER, 20, "10.20.0.2", 5353, 5353, p, n) == 1);
	free(p);
	CHECK(t.n == 4);

	lc_table_free(&t);
}

/* Every prefix and a few thousand random mutations must parse without
 * reading out of bounds (ASan/UBSan catch it if they do). */
static void test_robustness(const char *dir)
{
	static const struct { const char *file; uint16_t sport, dport; } s[] = {
		{ "mdns_printer.bin", 5353, 5353 },
		{ "mdns_scanner.bin",    5353, 5353 },
		{ "ssdp_notify.bin",     1900, 1900 },
		{ "dhcp_discover.bin",   68,   67   },
	};
	uint8_t mac[6] = { 0x02, 0, 0, 0, 0x10, 0 };
	unsigned seed = 12345;

	for (size_t k = 0; k < sizeof(s) / sizeof(s[0]); k++) {
		struct lc_table t;
		size_t n;
		uint8_t *p = load(dir, s[k].file, &n);

		lc_table_init(&t, 8, NULL);
		for (size_t cut = 0; cut <= n; cut++) {
			uint8_t *q = malloc(cut ? cut : 1);

			memcpy(q, p, cut);
			lc_feed(&t, mac, 0, "10.0.0.1", s[k].sport, s[k].dport, q, cut);
			free(q);
		}
		for (int i = 0; i < 3000; i++) {
			uint8_t *q = malloc(n);

			memcpy(q, p, n);
			for (int m = 0; m < 4; m++) {
				seed = seed * 1103515245u + 12345u;
				q[(seed >> 8) % n] = (uint8_t)(seed >> 16);
			}
			mac[5] = (uint8_t)i;
			lc_feed(&t, mac, 0, "10.0.0.1", s[k].sport, s[k].dport, q, n);
			free(q);
		}
		lc_table_free(&t);
		free(p);
	}
}

int main(int argc, char **argv)
{
	if (argc != 2) {
		fprintf(stderr, "usage: %s SAMPLE_DIR\n", argv[0]);
		return 2;
	}
	test_samples(argv[1]);
	test_robustness(argv[1]);
	if (failures) {
		fprintf(stderr, "%d check(s) failed\n", failures);
		return 1;
	}
	printf("parser tests: all passed\n");
	return 0;
}
