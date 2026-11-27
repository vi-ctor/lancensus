# lancensus

[![ci](https://github.com/vi-ctor/lancensus/actions/workflows/ci.yml/badge.svg)](https://github.com/vi-ctor/lancensus/actions/workflows/ci.yml)

**Passive LAN device discovery with eBPF.** See every printer, scanner, IP
camera, NAS and other networked device on a segment — hostnames, friendly
names, models, advertised services, DHCP fingerprints — **without sending a
single packet.**

```console
$ sudo ./lancensus -i eth0
{"mac":"02:00:00:00:00:02","vlan":0,"ips":["10.77.0.2"],"hostname":"office-printer","name":"Office Printer","model":"ExampleCo P400","services":["_ipp._tcp","urn:schemas-upnp-org:device:Printer:1"],"ssdp_server":"Linux/5.10 UPnP/1.0 ExamplePrint/1.0"}
{"mac":"02:00:00:00:00:03","vlan":0,"ips":["10.77.0.3"],"name":"Lab Scanner","model":"ExampleCo S200","services":["_uscan._tcp"]}
{"mac":"aa:bb:cc:dd:ee:01","vlan":0,"ips":["10.77.0.50"],"hostname":"ipcam-01","dhcp_vendor":"udhcp 1.36.1","dhcp_fp":"1,3,6,12,15,28,42"}
^C
MAC               VLAN  IP               HOSTNAME                  NAME / MODEL
02:00:00:00:00:02    0  10.77.0.2        office-printer            Office Printer / ExampleCo P400
02:00:00:00:00:03    0  10.77.0.3        -                         Lab Scanner / ExampleCo S200
aa:bb:cc:dd:ee:01    0  10.77.0.50       ipcam-01
3 device(s)
```

## Why

Active scanners (nmap, arp-scan) are noisy, get flagged by IDS, and miss
devices that sleep or ignore probes. But most networked devices already
announce themselves: they ask DHCP for an address, and printers, scanners,
NAS boxes and cameras advertise over mDNS/DNS-SD and SSDP. lancensus just
listens — from inside the kernel, on any interface, including VLAN trunks —
and turns those announcements into a device inventory.

Useful for homelabs, small-office networks, IoT VLAN audits, and for anyone
debugging "why can't I find the printer".

## How it works

```
 NIC ──► tc ingress (eBPF) ──────────────────────────► normal stack
              │  match UDP 5353 / 1900 / 68→67           (untouched:
              │  copy ≤1500 B payload + L2/L3 identity    always TC_ACT_OK)
              ▼
         BPF ring buffer
              │
              ▼
   userspace: mDNS / SSDP / DHCP parsers ──► device table ──► JSON lines
```

- **Kernel side stays tiny.** It only classifies and copies; it never drops,
  rewrites or injects. IPv4 and IPv6, 802.1Q tags (offloaded or in-band),
  IP fragments skipped.
- **Parsing lives in userspace**, where it is easy to test: DNS name
  compression with hop limits, TXT records (`ty=`, `usb_MDL=`, `product=`,
  `model=`), SRV/PTR/A/AAAA, SSDP `SERVER`/`USER-AGENT`/`NT`/`ST`, DHCP options
  12, 50, 55, 60.
- **DHCP is keyed on `chaddr`**, so relayed requests still map to the real
  client.
- **Same MAC on different VLANs = different devices.**
- Clean exit: the tc filter (and the clsact qdisc, if lancensus created it)
  is removed on Ctrl-C.

## Build

Linux, kernel 5.8+ (BPF ring buffer), clang, libbpf:

```sh
sudo apt-get install -y clang llvm libbpf-dev libelf-dev zlib1g-dev
make
sudo ./lancensus -i eth0          # or a VLAN/bridge/trunk interface
```

Options: `-b PATH` BPF object (default `./lancensus.bpf.o`), `-n N` max
devices (default 4096), `-q` no summary table.

## Tests

```sh
make check        # parser tests under ASan/UBSan — works on Linux and macOS
sudo make smoke   # end-to-end: veth pair + netns, real kernel verifier
```

`make check` runs known-good samples (including compressed DNS names), every
truncated prefix of each packet, and thousands of random mutations. CI runs
all three stages on every push.

## Roadmap

- IPv6 extension-header walk
- Egress hook (see the host's own announcements)
- LLDP / CDP / NetBIOS / WS-Discovery
- DHCP fingerprint → OS family hints
- Prometheus / SQLite output

## Author

Victor Cheng — available for Linux kernel networking and eBPF consulting: https://vi-ctor.github.io/consulting/

## License

MIT for userspace; the BPF program is dual MIT/GPL-2.0.
