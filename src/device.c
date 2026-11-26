// SPDX-License-Identifier: MIT
/*
 * Device table and parsers for mDNS (RFC 6762/6763), SSDP and DHCP
 * (RFC 2131/2132). Everything here treats the payload as hostile:
 * every read is bounds-checked, DNS compression pointers are hop-limited,
 * and strings are clamped and stripped of control characters.
 */
#include "device.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

/* ---------- small helpers ---------- */

static uint16_t rd16(const uint8_t *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

/* Copy up to n bytes into dst (cap bytes), replacing control chars,
 * trimming trailing spaces. Returns 1 if dst changed. */
static int set_str(char *dst, size_t cap, const char *src, size_t n)
{
	char tmp[LC_STR];
	size_t i, j = 0;

	if (cap > sizeof(tmp))
		cap = sizeof(tmp);
	for (i = 0; i < n && j + 1 < cap; i++) {
		unsigned char c = (unsigned char)src[i];

		if (c == '\0')
			break;
		tmp[j++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
	}
	while (j > 0 && tmp[j - 1] == ' ')
		j--;
	tmp[j] = '\0';
	if (j == 0 || strcmp(dst, tmp) == 0)
		return 0;
	memcpy(dst, tmp, j + 1);
	return 1;
}

static int ends_with_ci(const char *s, const char *suf)
{
	size_t ls = strlen(s), lf = strlen(suf);

	return ls >= lf && strcasecmp(s + ls - lf, suf) == 0;
}

/* "office-printer.local." -> "office-printer" */
static void strip_local(char *s)
{
	size_t l = strlen(s);

	while (l > 0 && s[l - 1] == '.')
		s[--l] = '\0';
	if (ends_with_ci(s, ".local"))
		s[l - 6] = '\0';
}

static int add_ip(struct lc_device *d, const char *ip)
{
	int i;

	if (!ip || !*ip || strcmp(ip, "0.0.0.0") == 0 || strcmp(ip, "::") == 0)
		return 0;
	for (i = 0; i < d->n_ips; i++)
		if (strcmp(d->ips[i], ip) == 0)
			return 0;
	if (d->n_ips >= LC_MAX_IPS)
		return 0;
	snprintf(d->ips[d->n_ips++], sizeof(d->ips[0]), "%s", ip);
	return 1;
}

static int add_svc(struct lc_device *d, const char *s, size_t n)
{
	char tmp[LC_SVC_STR];
	size_t i, j = 0;
	int k;

	for (i = 0; i < n && j + 1 < sizeof(tmp); i++) {
		unsigned char c = (unsigned char)s[i];

		if (c == '\0')
			break;
		tmp[j++] = (c < 0x20 || c == 0x7f) ? '?' : (char)c;
	}
	while (j > 0 && tmp[j - 1] == ' ')
		j--;
	tmp[j] = '\0';
	if (j == 0)
		return 0;
	for (k = 0; k < d->n_svcs; k++)
		if (strcmp(d->services[k], tmp) == 0)
			return 0;
	if (d->n_svcs >= LC_MAX_SVCS)
		return 0;
	memcpy(d->services[d->n_svcs++], tmp, j + 1);
	return 1;
}

int lc_has_service(const struct lc_device *d, const char *svc)
{
	int i;

	for (i = 0; i < d->n_svcs; i++)
		if (strcmp(d->services[i], svc) == 0)
			return 1;
	return 0;
}

/* ---------- table ---------- */

int lc_table_init(struct lc_table *t, size_t cap, FILE *out)
{
	t->devs = calloc(cap, sizeof(*t->devs));
	t->cap = t->devs ? cap : 0;
	t->n = 0;
	t->out = out;
	return t->devs ? 0 : -1;
}

void lc_table_free(struct lc_table *t)
{
	free(t->devs);
	t->devs = NULL;
	t->cap = t->n = 0;
}

const struct lc_device *lc_find(const struct lc_table *t,
				const uint8_t mac[6], uint16_t vlan)
{
	size_t i;

	for (i = 0; i < t->n; i++)
		if (t->devs[i].vlan == vlan && memcmp(t->devs[i].mac, mac, 6) == 0)
			return &t->devs[i];
	return NULL;
}

static struct lc_device *get_or_add(struct lc_table *t, const uint8_t mac[6],
				    uint16_t vlan, int *changed)
{
	struct lc_device *d = (struct lc_device *)lc_find(t, mac, vlan);

	if (d)
		return d;
	if (t->n >= t->cap)
		return NULL;
	d = &t->devs[t->n++];
	memset(d, 0, sizeof(*d));
	memcpy(d->mac, mac, 6);
	d->vlan = vlan;
	d->first_seen = time(NULL);
	*changed = 1;
	return d;
}

/* ---------- mDNS ---------- */

/* Read a possibly-compressed DNS name starting at *off into out.
 * On success advances *off past the name as stored at that position. */
static int dns_name(const uint8_t *p, size_t len, size_t *off,
		    char *out, size_t cap)
{
	size_t o = *off, j = 0;
	int jumped = 0, hops = 0;

	out[0] = '\0';
	for (;;) {
		uint8_t l;

		if (o >= len)
			return -1;
		l = p[o];
		if ((l & 0xC0) == 0xC0) {
			size_t ptr;

			if (o + 1 >= len)
				return -1;
			ptr = ((size_t)(l & 0x3F) << 8) | p[o + 1];
			if (!jumped)
				*off = o + 2;
			jumped = 1;
			if (++hops > 16 || ptr >= len)
				return -1;
			o = ptr;
			continue;
		}
		if (l & 0xC0)                    /* 0x40/0x80: reserved label types */
			return -1;
		if (l == 0) {
			if (!jumped)
				*off = o + 1;
			break;
		}
		o++;
		if (o + l > len)
			return -1;
		if (j > 0 && j + 1 < cap)
			out[j++] = '.';
		for (size_t i = 0; i < l; i++)
			if (j + 1 < cap)
				out[j++] = (char)p[o + i];
		o += l;
	}
	out[j] = '\0';
	return 0;
}

static int set_host(struct lc_device *d, const char *name)
{
	char tmp[256];

	snprintf(tmp, sizeof(tmp), "%s", name);
	strip_local(tmp);
	return set_str(d->hostname, sizeof(d->hostname), tmp, strlen(tmp));
}

static int txt_kv(struct lc_device *d, const uint8_t *s, size_t l)
{
	static const char *const keys[] = {
		"ty=",       /* DNS-SD printers/scanners (IPP, eSCL) */
		"usb_MDL=",  /* IEEE 1284 model string               */
		"product=",  /* "(Model Name)"                       */
		"model=",    /* generic                              */
	};
	size_t i;

	for (i = 0; i < sizeof(keys) / sizeof(keys[0]); i++) {
		size_t kl = strlen(keys[i]);
		const char *v = (const char *)s + kl;
		size_t vl = l - kl;

		if (l <= kl || strncasecmp((const char *)s, keys[i], kl) != 0)
			continue;
		if (vl >= 2 && v[0] == '(' && v[vl - 1] == ')') {
			v++;
			vl -= 2;
		}
		return set_str(d->model, LC_STR, v, vl);
	}
	return 0;
}

static int parse_mdns(struct lc_device *d, const uint8_t *p, size_t len)
{
	char name[256], tgt[256];
	unsigned qd, rr, i;
	size_t off = 12;
	int ch = 0;

	if (len < 12)
		return 0;
	if (!(rd16(p + 2) & 0x8000))      /* queries reveal presence only */
		return 0;
	qd = rd16(p + 4);
	rr = (unsigned)rd16(p + 6) + rd16(p + 8) + rd16(p + 10);

	for (i = 0; i < qd; i++) {
		if (dns_name(p, len, &off, name, sizeof(name)) < 0)
			return ch;
		off += 4;
		if (off > len)
			return ch;
	}

	for (i = 0; i < rr; i++) {
		uint16_t type, rdlen;
		size_t rd, o;

		if (dns_name(p, len, &off, name, sizeof(name)) < 0)
			return ch;
		if (off + 10 > len)
			return ch;
		type = rd16(p + off);
		rdlen = rd16(p + off + 8);
		off += 10;
		if (off + rdlen > len)
			return ch;
		rd = off;
		off += rdlen;

		switch (type) {
		case 1:   /* A */
		case 28:  /* AAAA */ {
			char ip[46];
			int af = type == 1 ? AF_INET : AF_INET6;

			if ((type == 1 && rdlen != 4) || (type == 28 && rdlen != 16))
				break;
			ch |= set_host(d, name);
			if (inet_ntop(af, p + rd, ip, sizeof(ip)))
				ch |= add_ip(d, ip);
			break;
		}
		case 12:  /* PTR */
			o = rd;
			if (dns_name(p, len, &o, tgt, sizeof(tgt)) < 0)
				break;
			if (ends_with_ci(name, ".arpa")) {          /* reverse map */
				ch |= set_host(d, tgt);
			} else if (name[0] == '_' &&
				   strncasecmp(name, "_services._dns-sd.", 18) != 0) {
				char *dot;

				strip_local(name);
				ch |= add_svc(d, name, strlen(name));
				/* Instance label is a good friendly-name fallback. */
				dot = strchr(tgt, '.');
				if (dot && !d->name[0])
					ch |= set_str(d->name, sizeof(d->name), tgt,
						      (size_t)(dot - tgt));
			}
			break;
		case 33:  /* SRV: prio, weight, port, target */
			if (rdlen <= 6)
				break;
			o = rd + 6;
			if (dns_name(p, len, &o, tgt, sizeof(tgt)) == 0)
				ch |= set_host(d, tgt);
			break;
		case 16:  /* TXT */
			o = rd;
			while (o < rd + rdlen) {
				uint8_t l = p[o++];

				if (o + l > rd + rdlen)
					break;
				ch |= txt_kv(d, p + o, l);
				o += l;
			}
			break;
		}
	}
	return ch;
}

/* ---------- SSDP ---------- */

static int hdr(const char *line, size_t n, const char *key,
	       const char **val, size_t *vn)
{
	size_t kl = strlen(key);

	if (n < kl || strncasecmp(line, key, kl) != 0)
		return 0;
	line += kl;
	n -= kl;
	while (n > 0 && (*line == ' ' || *line == '\t')) {
		line++;
		n--;
	}
	*val = line;
	*vn = n;
	return 1;
}

static int parse_ssdp(struct lc_device *d, const uint8_t *p, size_t len)
{
	size_t i = 0;
	int ch = 0;

	while (i < len) {
		size_t s = i, e, vn;
		const char *line, *v;

		while (i < len && p[i] != '\n')
			i++;
		e = i;
		if (i < len)
			i++;
		if (e > s && p[e - 1] == '\r')
			e--;
		line = (const char *)p + s;

		if (hdr(line, e - s, "SERVER:", &v, &vn) ||
		    hdr(line, e - s, "USER-AGENT:", &v, &vn)) {
			ch |= set_str(d->ssdp_server, sizeof(d->ssdp_server), v, vn);
		} else if (hdr(line, e - s, "NT:", &v, &vn) ||
			   hdr(line, e - s, "ST:", &v, &vn)) {
			if (!(vn >= 5 && strncasecmp(v, "uuid:", 5) == 0) &&
			    !(vn == 8 && strncasecmp(v, "ssdp:all", 8) == 0))
				ch |= add_svc(d, v, vn);
		}
	}
	return ch;
}

/* ---------- DHCP (client -> server) ---------- */

static int parse_dhcp_opts(struct lc_device *d, const uint8_t *p, size_t len)
{
	size_t o = 240;
	int ch = 0;

	while (o < len) {
		uint8_t code = p[o++], l;

		if (code == 0)
			continue;
		if (code == 255 || o >= len)
			break;
		l = p[o++];
		if (o + l > len)
			break;
		switch (code) {
		case 12:  /* host name */
			ch |= set_str(d->hostname, sizeof(d->hostname),
				      (const char *)p + o, l);
			break;
		case 60:  /* vendor class identifier */
			ch |= set_str(d->dhcp_vendor, sizeof(d->dhcp_vendor),
				      (const char *)p + o, l);
			break;
		case 55: { /* parameter request list = OS fingerprint */
			char fp[LC_STR];
			size_t k, j = 0;

			fp[0] = '\0';
			for (k = 0; k < l && j < sizeof(fp); k++) {
				int w = snprintf(fp + j, sizeof(fp) - j,
						 k ? ",%u" : "%u", p[o + k]);
				if (w < 0 || (size_t)w >= sizeof(fp) - j)
					break;
				j += (size_t)w;
			}
			ch |= set_str(d->dhcp_fp, sizeof(d->dhcp_fp), fp, j);
			break;
		}
		case 50:  /* requested IP address */
			if (l == 4) {
				char ip[16];

				if (inet_ntop(AF_INET, p + o, ip, sizeof(ip)))
					ch |= add_ip(d, ip);
			}
			break;
		}
		o += l;
	}
	return ch;
}

/* ---------- output ---------- */

static void jstr(FILE *f, const char *s)
{
	fputc('"', f);
	for (; *s; s++) {
		unsigned char c = (unsigned char)*s;

		if (c == '"' || c == '\\') {
			fputc('\\', f);
			fputc(c, f);
		} else if (c < 0x20) {
			fprintf(f, "\\u%04x", c);
		} else {
			fputc(c, f);
		}
	}
	fputc('"', f);
}

static void jfield(FILE *f, const char *key, const char *val)
{
	if (!val[0])
		return;
	fprintf(f, ",\"%s\":", key);
	jstr(f, val);
}

static void emit_json(FILE *f, const struct lc_device *d)
{
	int i;

	fprintf(f, "{\"ts\":%lld,\"mac\":\"%02x:%02x:%02x:%02x:%02x:%02x\",\"vlan\":%u",
		(long long)d->last_seen, d->mac[0], d->mac[1], d->mac[2],
		d->mac[3], d->mac[4], d->mac[5], d->vlan);
	if (d->n_ips) {
		fputs(",\"ips\":[", f);
		for (i = 0; i < d->n_ips; i++) {
			if (i)
				fputc(',', f);
			jstr(f, d->ips[i]);
		}
		fputc(']', f);
	}
	jfield(f, "hostname", d->hostname);
	jfield(f, "name", d->name);
	jfield(f, "model", d->model);
	if (d->n_svcs) {
		fputs(",\"services\":[", f);
		for (i = 0; i < d->n_svcs; i++) {
			if (i)
				fputc(',', f);
			jstr(f, d->services[i]);
		}
		fputc(']', f);
	}
	jfield(f, "ssdp_server", d->ssdp_server);
	jfield(f, "dhcp_vendor", d->dhcp_vendor);
	jfield(f, "dhcp_fp", d->dhcp_fp);
	fputs("}\n", f);
	fflush(f);
}

/* ---------- entry point ---------- */

int lc_feed(struct lc_table *t, const uint8_t mac[6], uint16_t vlan,
	    const char *ip, uint16_t sport, uint16_t dport,
	    const uint8_t *p, size_t len)
{
	static const uint8_t cookie[4] = { 99, 130, 83, 99 };
	struct lc_device *d;
	int ch = 0;

	if (sport == 68 && dport == 67) {
		/* BOOTREQUEST with magic cookie; key on chaddr, not the
		 * L2 source, so relayed requests still map to the client. */
		if (len < 240 || p[0] != 1 || memcmp(p + 236, cookie, 4) != 0)
			return 0;
		d = get_or_add(t, p + 28, vlan, &ch);
		if (!d)
			return 0;
		ch |= parse_dhcp_opts(d, p, len);
	} else {
		d = get_or_add(t, mac, vlan, &ch);
		if (!d)
			return 0;
		ch |= add_ip(d, ip);
		if (sport == 5353 || dport == 5353)
			ch |= parse_mdns(d, p, len);
		else if (sport == 1900 || dport == 1900)
			ch |= parse_ssdp(d, p, len);
	}
	d->last_seen = time(NULL);
	if (ch && t->out)
		emit_json(t->out, d);
	return ch;
}

void lc_print_summary(const struct lc_table *t, FILE *f)
{
	size_t i;

	fprintf(f, "\n%-17s %4s  %-15s  %-24s  %s\n",
		"MAC", "VLAN", "IP", "HOSTNAME", "NAME / MODEL");
	for (i = 0; i < t->n; i++) {
		const struct lc_device *d = &t->devs[i];

		fprintf(f, "%02x:%02x:%02x:%02x:%02x:%02x %4u  %-15s  %-24s  %s%s%s\n",
			d->mac[0], d->mac[1], d->mac[2], d->mac[3], d->mac[4],
			d->mac[5], d->vlan, d->n_ips ? d->ips[0] : "-",
			d->hostname[0] ? d->hostname : "-",
			d->name, d->name[0] && d->model[0] ? " / " : "",
			d->model);
	}
	fprintf(f, "%zu device(s)\n", t->n);
}
