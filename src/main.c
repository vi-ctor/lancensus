// SPDX-License-Identifier: MIT
/* lancensus: load the tc classifier, read events, print device JSON lines. */
#include <arpa/inet.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <signal.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "device.h"
#include "lancensus.h"

#define LC_TC_HANDLE 0x4c43   /* "LC" */
#define LC_TC_PRIO   0x4c43

static volatile sig_atomic_t stop;

static void on_signal(int sig)
{
	(void)sig;
	stop = 1;
}

static int on_event(void *ctx, void *data, size_t size)
{
	struct lc_table *t = ctx;
	const struct lc_event *e = data;
	char ip[INET6_ADDRSTRLEN] = "";
	size_t n;

	if (size < offsetof(struct lc_event, payload))
		return 0;
	inet_ntop(e->family == 6 ? AF_INET6 : AF_INET, e->src_ip, ip, sizeof(ip));
	n = e->payload_len;
	if (n > LC_MAX_PAYLOAD || n > size - offsetof(struct lc_event, payload))
		return 0;
	lc_feed(t, e->src_mac, e->vlan, ip, e->sport, e->dport, e->payload, n);
	return 0;
}

static void usage(const char *prog)
{
	fprintf(stderr,
		"usage: %s -i IFACE [-b lancensus.bpf.o] [-n MAX_DEVICES] [-q]\n"
		"  Passively lists devices seen via mDNS, SSDP and DHCP.\n"
		"  Prints one JSON line per device change on stdout and a\n"
		"  summary table on stderr at exit. Needs CAP_BPF+CAP_NET_ADMIN.\n"
		"  -q  no summary table\n", prog);
}

int main(int argc, char **argv)
{
	const char *iface = NULL, *bpf_path = "lancensus.bpf.o";
	size_t max_devs = 4096;
	int quiet = 0, opt, err = 0, created_hook = 0, attached = 0;
	struct bpf_object *obj = NULL;
	struct bpf_program *prog;
	struct bpf_map *map;
	struct ring_buffer *rb = NULL;
	struct lc_table table = { 0 };
	unsigned int ifindex;
	LIBBPF_OPTS(bpf_tc_hook, hook, .attach_point = BPF_TC_INGRESS);
	LIBBPF_OPTS(bpf_tc_opts, tc, .handle = LC_TC_HANDLE, .priority = LC_TC_PRIO);

	while ((opt = getopt(argc, argv, "i:b:n:qh")) != -1) {
		switch (opt) {
		case 'i': iface = optarg; break;
		case 'b': bpf_path = optarg; break;
		case 'n': max_devs = strtoul(optarg, NULL, 10); break;
		case 'q': quiet = 1; break;
		default: usage(argv[0]); return opt == 'h' ? 0 : 2;
		}
	}
	if (!iface || max_devs == 0) {
		usage(argv[0]);
		return 2;
	}
	ifindex = if_nametoindex(iface);
	if (!ifindex) {
		fprintf(stderr, "lancensus: unknown interface %s\n", iface);
		return 1;
	}

	setvbuf(stdout, NULL, _IOLBF, 0);
	if (lc_table_init(&table, max_devs, stdout) < 0) {
		fprintf(stderr, "lancensus: out of memory\n");
		return 1;
	}

	obj = bpf_object__open_file(bpf_path, NULL);
	if (!obj) {
		err = -errno;
		fprintf(stderr, "lancensus: open %s: %s\n", bpf_path, strerror(errno));
		goto out;
	}
	err = bpf_object__load(obj);
	if (err) {
		fprintf(stderr, "lancensus: load BPF object: %s\n", strerror(-err));
		goto out;
	}
	prog = bpf_object__find_program_by_name(obj, "lancensus_ingress");
	map = bpf_object__find_map_by_name(obj, "events");
	if (!prog || !map) {
		fprintf(stderr, "lancensus: program or map missing in %s\n", bpf_path);
		err = -ENOENT;
		goto out;
	}

	hook.ifindex = (int)ifindex;
	tc.prog_fd = bpf_program__fd(prog);

	err = bpf_tc_hook_create(&hook);
	if (err == 0)
		created_hook = 1;
	else if (err != -EEXIST) {
		fprintf(stderr, "lancensus: create clsact on %s: %s\n",
			iface, strerror(-err));
		goto out;
	}
	err = bpf_tc_attach(&hook, &tc);
	if (err) {
		fprintf(stderr, "lancensus: attach to %s: %s\n", iface, strerror(-err));
		goto out;
	}
	attached = 1;

	rb = ring_buffer__new(bpf_map__fd(map), on_event, &table, NULL);
	if (!rb) {
		err = -errno;
		fprintf(stderr, "lancensus: ring buffer: %s\n", strerror(errno));
		goto out;
	}

	signal(SIGINT, on_signal);
	signal(SIGTERM, on_signal);
	fprintf(stderr, "lancensus: listening on %s (Ctrl-C to stop)\n", iface);

	while (!stop) {
		err = ring_buffer__poll(rb, 250);
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			fprintf(stderr, "lancensus: poll: %s\n", strerror(-err));
			break;
		}
		err = 0;
	}
	/* Drain anything still queued. */
	ring_buffer__consume(rb);

out:
	if (attached) {
		tc.flags = tc.prog_fd = tc.prog_id = 0;
		bpf_tc_detach(&hook, &tc);
	}
	if (created_hook) {
		hook.attach_point = BPF_TC_INGRESS | BPF_TC_EGRESS;
		bpf_tc_hook_destroy(&hook);
	}
	ring_buffer__free(rb);
	bpf_object__close(obj);
	if (!quiet && table.devs)
		lc_print_summary(&table, stderr);
	lc_table_free(&table);
	return err ? 1 : 0;
}
