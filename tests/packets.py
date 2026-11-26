#!/usr/bin/env python3
"""Build sample discovery packets.

  packets.py dump DIR      write payloads as .bin files (for parser tests)
  packets.py send DST_IP   send them over UDP from the right source ports
"""
import os
import socket
import struct
import sys


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\0"


def rr(owner: bytes, rtype: int, rdata: bytes, cls: int = 1, ttl: int = 120) -> bytes:
    return owner + struct.pack("!HHIH", rtype, cls, ttl, len(rdata)) + rdata


def txt(*items: bytes) -> bytes:
    return b"".join(bytes([len(s)]) + s for s in items)


def mdns_header(n_answers: int) -> bytes:
    # id 0, flags: response + authoritative
    return struct.pack("!HHHHHH", 0, 0x8400, 0, n_answers, 0, 0)


def mdns_printer() -> bytes:
    """An IPP printer announcing itself (PTR, SRV, TXT, A)."""
    inst = "Office Printer._ipp._tcp.local"
    recs = [
        rr(dns_name("_ipp._tcp.local"), 12, dns_name(inst)),
        rr(dns_name(inst), 33, struct.pack("!HHH", 0, 0, 631) + dns_name("office-printer.local"), cls=0x8001),
        rr(dns_name(inst), 16, txt(b"txtvers=1", b"rp=ipp/print", b"ty=ExampleCo P400")),
        rr(dns_name("office-printer.local"), 1, socket.inet_aton("10.77.0.2"), cls=0x8001),
    ]
    return mdns_header(len(recs)) + b"".join(recs)


def mdns_scanner() -> bytes:
    """An eSCL scanner; uses DNS name compression, like real responders do."""
    svc = dns_name("_uscan._tcp.local")              # at offset 12
    instance_label = b"Lab Scanner"
    ptr_rdata = bytes([len(instance_label)]) + instance_label + b"\xc0\x0c"
    ptr = svc + struct.pack("!HHIH", 12, 1, 4500, len(ptr_rdata)) + ptr_rdata
    inst_off = 12 + len(svc) + 10                     # where ptr_rdata starts
    assert inst_off < 256
    txt_rr = rr(b"\xc0" + bytes([inst_off]), 16, txt(b"rs=eSCL", b"product=(ExampleCo S200)"), cls=0x8001)
    return mdns_header(2) + ptr + txt_rr


def ssdp_notify() -> bytes:
    """The same printer advertising over UPnP."""
    return (
        b"NOTIFY * HTTP/1.1\r\n"
        b"HOST: 239.255.255.250:1900\r\n"
        b"CACHE-CONTROL: max-age=1800\r\n"
        b"LOCATION: http://10.77.0.2:80/upnp/desc.xml\r\n"
        b"NT: urn:schemas-upnp-org:device:Printer:1\r\n"
        b"NTS: ssdp:alive\r\n"
        b"SERVER: Linux/5.10 UPnP/1.0 ExamplePrint/1.0\r\n"
        b"USN: uuid:1234::urn:schemas-upnp-org:device:Printer:1\r\n\r\n"
    )


CLIENT_MAC = bytes.fromhex("aabbccddee01")


def dhcp_discover() -> bytes:
    """An IP camera (embedded Linux, BusyBox udhcpc) asking for an address."""
    bootp = struct.pack("!BBBBIHHIIII", 1, 1, 6, 0, 0x1234, 0, 0x8000, 0, 0, 0, 0)
    bootp += CLIENT_MAC + b"\0" * 10 + b"\0" * 192 + bytes([99, 130, 83, 99])
    opts = bytes([53, 1, 1])
    opts += bytes([12, 8]) + b"ipcam-01"
    opts += bytes([60, 12]) + b"udhcp 1.36.1"
    opts += bytes([55, 7, 1, 3, 6, 12, 15, 28, 42])
    opts += bytes([50, 4]) + socket.inet_aton("10.77.0.50")
    opts += b"\xff"
    return bootp + opts


SAMPLES = {
    "mdns_printer.bin": mdns_printer,
    "mdns_scanner.bin": mdns_scanner,
    "ssdp_notify.bin": ssdp_notify,
    "dhcp_discover.bin": dhcp_discover,
}


def dump(directory: str) -> None:
    os.makedirs(directory, exist_ok=True)
    for fname, fn in SAMPLES.items():
        with open(os.path.join(directory, fname), "wb") as f:
            f.write(fn())


def udp_send(payload: bytes, sport: int, dst: str, dport: int, broadcast: bool = False) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    if broadcast:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.bind(("", sport))
    s.sendto(payload, (dst, dport))
    s.close()


def send(dst: str) -> None:
    udp_send(mdns_printer(), 5353, dst, 5353)
    udp_send(ssdp_notify(), 1900, dst, 1900)
    udp_send(dhcp_discover(), 68, dst, 67, broadcast=True)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("dump", "send"):
        sys.exit(__doc__)
    (dump if sys.argv[1] == "dump" else send)(sys.argv[2])
