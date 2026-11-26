#!/usr/bin/env bash
# End-to-end test: attach lancensus to one end of a veth pair, send sample
# discovery packets from a network namespace on the other end, and check
# the JSON output. Needs root (netns + BPF). Run from the repo root.
set -euo pipefail

NS=lc-test
HOST_IF=lc-host
PEER_IF=lc-peer
OUT=$(mktemp)
ERR=$(mktemp)

cleanup() {
	[[ -n "${PID:-}" ]] && kill -INT "$PID" 2>/dev/null || true
	ip link del "$HOST_IF" 2>/dev/null || true
	ip netns del "$NS" 2>/dev/null || true
	rm -f "$OUT" "$ERR"
}
trap cleanup EXIT

ip netns add "$NS"
ip link add "$HOST_IF" type veth peer name "$PEER_IF" netns "$NS"
ip addr add 10.77.0.1/24 dev "$HOST_IF"
ip link set "$HOST_IF" up
ip -n "$NS" addr add 10.77.0.2/24 dev "$PEER_IF"
ip -n "$NS" link set "$PEER_IF" up
ip -n "$NS" link set lo up

./lancensus -i "$HOST_IF" -b ./lancensus.bpf.o >"$OUT" 2>"$ERR" &
PID=$!
sleep 1

if ! kill -0 "$PID" 2>/dev/null; then
	echo "lancensus exited early:"; cat "$ERR"; exit 1
fi

ip netns exec "$NS" python3 tests/packets.py send 10.77.0.1
sleep 1
kill -INT "$PID"
wait "$PID" || { echo "lancensus failed:"; cat "$ERR"; exit 1; }
PID=

echo "--- stdout"; cat "$OUT"
echo "--- stderr"; cat "$ERR"

fail=0
expect() {
	if grep -qF -- "$1" "$OUT"; then echo "ok   $1"; else echo "MISS $1"; fail=1; fi
}
expect '"hostname":"office-printer"'
expect '"name":"Office Printer"'
expect '"model":"ExampleCo P400"'
expect '"_ipp._tcp"'
expect '"ssdp_server":"Linux/5.10 UPnP/1.0 ExamplePrint/1.0"'
expect '"mac":"aa:bb:cc:dd:ee:01"'
expect '"hostname":"ipcam-01"'
expect '"dhcp_fp":"1,3,6,12,15,28,42"'

# The classifier must be gone after exit.
if tc filter show dev "$HOST_IF" ingress 2>/dev/null | grep -q bpf; then
	echo "MISS tc filter removed on exit"; fail=1
else
	echo "ok   tc filter removed on exit"
fi
exit $fail
