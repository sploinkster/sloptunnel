#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
LAB_DIR="${SLOPTUNNEL_WINDOWS_LAB_DIR:-$ROOT_DIR/lab/windows}"
ISO="${SLOPTUNNEL_WINDOWS_ISO:-$LAB_DIR/SERVER_EVAL_x64FRE_en-us.iso}"
ANSWER_ISO="$LAB_DIR/sloptunnel-answer.iso"
DISK="$LAB_DIR/winserver.qcow2"
RESULTS="$LAB_DIR/results"
MONITOR="$LAB_DIR/qemu-monitor.sock"
VNC_SOCKET="$LAB_DIR/qemu-vnc.sock"
CLIENT_NS="${SLOPTUNNEL_WINDOWS_CLIENT_NS:-slop-win-client}"
FW_NS="${SLOPTUNNEL_WINDOWS_FW_NS:-slop-win-fw}"
SERVER_IP="${SLOPTUNNEL_SERVER_IP:-18.219.84.252}"
DNS_DOMAIN="${SLOPTUNNEL_DNS_DOMAIN:-sploinkstersploinkster.online}"
TCP_PORT="${SLOPTUNNEL_TCP_PORT:-5223}"
QEMU_TIMEOUT="${SLOPTUNNEL_WINDOWS_QEMU_TIMEOUT:-7200}"

need_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "run as root so the lab can create namespaces and firewall rules" >&2
    exit 1
  fi
}

cleanup() {
  set +e
  if [[ -n "${QEMU_PID:-}" ]]; then
    kill "$QEMU_PID" >/dev/null 2>&1
    wait "$QEMU_PID" >/dev/null 2>&1
  fi
  if [[ -n "${CLIENT_DHCP_PID:-}" ]]; then
    kill "$CLIENT_DHCP_PID" >/dev/null 2>&1
    wait "$CLIENT_DHCP_PID" >/dev/null 2>&1
  fi
  if [[ -n "${DNSMASQ_PID:-}" ]]; then
    kill "$DNSMASQ_PID" >/dev/null 2>&1
    wait "$DNSMASQ_PID" >/dev/null 2>&1
  fi
  if [[ -n "${HOST_DEV:-}" ]]; then
    iptables -t nat -D POSTROUTING -s 10.211.0.0/24 -o "$HOST_DEV" -j MASQUERADE >/dev/null 2>&1
    iptables -D FORWARD -i stw-wan-h -o "$HOST_DEV" -j ACCEPT >/dev/null 2>&1
    iptables -D FORWARD -i "$HOST_DEV" -o stw-wan-h -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1
  fi
  ip netns del "$CLIENT_NS" >/dev/null 2>&1
  ip netns del "$FW_NS" >/dev/null 2>&1
  ip link del stw-wan-h >/dev/null 2>&1
  ip link del stw-c >/dev/null 2>&1
  rm -rf "/etc/netns/$CLIENT_NS"
}
trap cleanup EXIT

need_root

for cmd in ip iptables dnsmasq qemu-img qemu-system-x86_64 timeout; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "missing required command: $cmd" >&2
    exit 1
  }
done

if [[ ! -r "$ISO" ]]; then
  echo "missing Windows Server ISO: $ISO" >&2
  exit 1
fi
if [[ ! -r "$ANSWER_ISO" ]]; then
  "$ROOT_DIR/scripts/windows_lab/make_answer_iso.sh"
fi

mkdir -p "$RESULTS"
printf 'sloptunnel windows results\n' > "$RESULTS/SLOPTUNNEL_RESULTS.txt"
rm -f "$RESULTS/DONE.txt" "$RESULTS/done.txt" "$RESULTS/windows-result.txt" \
  "$RESULTS/sloptunnel.out" "$RESULTS/sloptunnel.err" \
  "$RESULTS/sloptunnel-novpn.out" "$RESULTS/sloptunnel-novpn.err" \
  "$RESULTS/help.out" "$RESULTS/help.err" \
  "$RESULTS/dns.out" "$RESULTS/dns.err" "$RESULTS/tcp.out" "$RESULTS/tcp.err" \
  "$RESULTS/stack.out" "$RESULTS/stack.err" "$RESULTS/vpn.out" "$RESULTS/vpn.err"
rm -f "$MONITOR" "$VNC_SOCKET"

if [[ ! -r "$DISK" ]]; then
  qemu-img create -f qcow2 "$DISK" 32G
fi

HOST_DEV="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
if [[ -z "$HOST_DEV" ]]; then
  echo "could not detect host egress interface" >&2
  exit 1
fi

cleanup
trap cleanup EXIT

ip netns add "$CLIENT_NS"
ip netns add "$FW_NS"

ip link add stw-c type veth peer name stw-f
ip link set stw-c netns "$CLIENT_NS"
ip link set stw-f netns "$FW_NS"

ip link add stw-wan-h type veth peer name stw-wan-f
ip link set stw-wan-f netns "$FW_NS"

ip addr add 10.211.0.1/24 dev stw-wan-h
ip link set stw-wan-h up

ip netns exec "$CLIENT_NS" ip link set lo up
ip netns exec "$CLIENT_NS" ip link add stw-br0 type bridge
ip netns exec "$CLIENT_NS" ip link set stw-br0 up
ip netns exec "$CLIENT_NS" ip addr add 10.210.0.2/24 dev stw-br0
ip netns exec "$CLIENT_NS" ip link set stw-c master stw-br0
ip netns exec "$CLIENT_NS" ip link set stw-c up
ip netns exec "$CLIENT_NS" ip tuntap add dev stw-tap0 mode tap
ip netns exec "$CLIENT_NS" ip link set stw-tap0 master stw-br0
ip netns exec "$CLIENT_NS" ip link set stw-tap0 up
ip netns exec "$CLIENT_NS" ip route add default via 10.210.0.1

ip netns exec "$FW_NS" ip link set lo up
ip netns exec "$FW_NS" ip addr add 10.210.0.1/24 dev stw-f
ip netns exec "$FW_NS" ip link set stw-f up
ip netns exec "$FW_NS" ip addr add 10.211.0.2/24 dev stw-wan-f
ip netns exec "$FW_NS" ip link set stw-wan-f up
ip netns exec "$FW_NS" ip route add default via 10.211.0.1

mkdir -p "/etc/netns/$CLIENT_NS"
printf 'nameserver 10.210.0.1\n' > "/etc/netns/$CLIENT_NS/resolv.conf"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$FW_NS" sysctl -w net.ipv4.ip_forward=1 >/dev/null

iptables -t nat -C POSTROUTING -s 10.211.0.0/24 -o "$HOST_DEV" -j MASQUERADE >/dev/null 2>&1 ||
  iptables -t nat -A POSTROUTING -s 10.211.0.0/24 -o "$HOST_DEV" -j MASQUERADE
iptables -C FORWARD -i stw-wan-h -o "$HOST_DEV" -j ACCEPT >/dev/null 2>&1 ||
  iptables -A FORWARD -i stw-wan-h -o "$HOST_DEV" -j ACCEPT
iptables -C FORWARD -i "$HOST_DEV" -o stw-wan-h -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 ||
  iptables -A FORWARD -i "$HOST_DEV" -o stw-wan-h -m state --state RELATED,ESTABLISHED -j ACCEPT

ip netns exec "$FW_NS" iptables -P INPUT DROP
ip netns exec "$FW_NS" iptables -P OUTPUT DROP
ip netns exec "$FW_NS" iptables -P FORWARD DROP
ip netns exec "$FW_NS" iptables -A INPUT -i lo -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -o lo -j ACCEPT
ip netns exec "$FW_NS" iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec "$FW_NS" iptables -A INPUT -i stw-f -p udp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A INPUT -i stw-f -p tcp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -o stw-wan-f -p udp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -o stw-wan-f -p tcp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec "$FW_NS" iptables -A FORWARD -i stw-f -o stw-wan-f -p tcp --dport "$TCP_PORT" -j ACCEPT
ip netns exec "$FW_NS" iptables -t nat -A POSTROUTING -s 10.210.0.0/24 -o stw-wan-f -j MASQUERADE

DNSMASQ_LOG="$LAB_DIR/windows-dnsmasq.log"
rm -f "$DNSMASQ_LOG"
ip netns exec "$FW_NS" dnsmasq --no-daemon --no-hosts --no-resolv \
  --listen-address=10.210.0.1 --bind-interfaces --server="/$DNS_DOMAIN/$SERVER_IP" \
  --log-queries --log-facility=- > "$DNSMASQ_LOG" 2>&1 &
DNSMASQ_PID="$!"
sleep 1

CLIENT_DHCP_LOG="$LAB_DIR/windows-client-dhcp.log"
rm -f "$CLIENT_DHCP_LOG"
ip netns exec "$CLIENT_NS" dnsmasq --no-daemon --no-hosts --no-resolv --port=0 \
  --interface=stw-br0 --bind-interfaces \
  --dhcp-range=10.210.0.50,10.210.0.80,255.255.255.0,1h \
  --dhcp-option=option:router,10.210.0.1 \
  --dhcp-option=option:dns-server,10.210.0.1 \
  --log-dhcp --log-facility=- > "$CLIENT_DHCP_LOG" 2>&1 &
CLIENT_DHCP_PID="$!"
sleep 1

echo "preflight: direct host namespace route exists; Windows VM traffic is constrained inside $CLIENT_NS"
echo "starting Windows Server VM under QEMU TCG; timeout ${QEMU_TIMEOUT}s"

QEMU_NET_OPTS="tap,id=n0,ifname=stw-tap0,script=no,downscript=no"
QEMU_ARGS=(
  -machine accel=tcg
  -cpu qemu64
  -smp 2
  -m 4096
  -display none
  -vnc "unix:$VNC_SOCKET"
  -monitor "unix:$MONITOR,server=on,wait=off"
  -serial "file:$LAB_DIR/windows-serial.log"
  -drive "file=$DISK,if=ide,index=0,media=disk,format=qcow2"
  -drive "file=$ISO,if=ide,index=1,media=cdrom,readonly=on"
  -drive "file=$ANSWER_ISO,if=ide,index=2,media=cdrom,readonly=on"
  -drive "file=fat:rw:$RESULTS,if=ide,index=3,media=disk,format=raw"
  -netdev "$QEMU_NET_OPTS"
  -device e1000,netdev=n0
  -boot once=d,order=c,menu=off
)

ip netns exec "$CLIENT_NS" timeout "$QEMU_TIMEOUT" qemu-system-x86_64 "${QEMU_ARGS[@]}" &
QEMU_PID="$!"

for _ in $(seq 1 20); do
  [[ -S "$MONITOR" ]] && break
  sleep 1
done
if [[ -S "$MONITOR" ]]; then
  {
    sleep 2
    printf 'sendkey ret\n'
    sleep 1
    printf 'sendkey ret\n'
  } | nc -UN "$MONITOR" >/dev/null 2>&1 || true
fi

while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
  if [[ -r "$RESULTS/DONE.txt" || -r "$RESULTS/done.txt" ]]; then
    echo "Windows guest reported completion"
    break
  fi
  sleep 10
done

wait "$QEMU_PID" || true
QEMU_PID=""

if [[ ! -r "$RESULTS/windows-result.txt" ]]; then
  echo "Windows result file was not produced" >&2
  echo "serial tail:" >&2
  tail -80 "$LAB_DIR/windows-serial.log" >&2 || true
  exit 1
fi

grep -q 'query\[TXT\]' "$DNSMASQ_LOG" || {
  tail -80 "$DNSMASQ_LOG" >&2 || true
  echo "no DNS TXT tunnel queries were observed from the Windows lab" >&2
  exit 1
}

echo "Windows result:"
tail -80 "$RESULTS/windows-result.txt"
echo "DNS TXT sample:"
awk '/query\[TXT\]/ { print substr($0, 1, 220); count++; if (count == 5) exit }' "$DNSMASQ_LOG"

grep -q 'tunnel_http_exit=0' "$RESULTS/windows-result.txt" || {
  echo "Windows full-tunnel HTTP test did not succeed" >&2
  exit 1
}
