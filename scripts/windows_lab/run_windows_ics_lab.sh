#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BASE_LAB_DIR="${SLOPTUNNEL_WINDOWS_BASE_LAB_DIR:-$ROOT_DIR/lab/windows}"
LAB_DIR="${SLOPTUNNEL_WINDOWS_ICS_LAB_DIR:-$ROOT_DIR/lab/windows-ics}"
ISO="${SLOPTUNNEL_WINDOWS_ISO:-$BASE_LAB_DIR/SERVER_EVAL_x64FRE_en-us.iso}"
ANSWER_ISO="$LAB_DIR/sloptunnel-ics-answer.iso"
ANSWER_DIR="$LAB_DIR/answer"
DISK="$LAB_DIR/winserver-ics.qcow2"
RESULTS="$LAB_DIR/results"
MONITOR="$LAB_DIR/qemu-monitor.sock"
VNC_SOCKET="$LAB_DIR/qemu-vnc.sock"
WIN_NS="${SLOPTUNNEL_ICS_WIN_NS:-slop-ics-win}"
FW_NS="${SLOPTUNNEL_ICS_FW_NS:-slop-ics-fw}"
LAN_NS="${SLOPTUNNEL_ICS_LAN_NS:-slop-ics-lan}"
SERVER_IP="${SLOPTUNNEL_SERVER_IP:-18.219.84.252}"
DNS_DOMAIN="${SLOPTUNNEL_DNS_DOMAIN:-sploinkstersploinkster.online}"
TCP_PORT="${SLOPTUNNEL_TCP_PORT:-5223}"
TOKEN_FILE="${SLOPTUNNEL_TOKEN_FILE:-$ROOT_DIR/keys/sloptunnel-token.txt}"
QEMU_TIMEOUT="${SLOPTUNNEL_WINDOWS_QEMU_TIMEOUT:-7200}"
QEMU_ACCEL="${SLOPTUNNEL_QEMU_ACCEL:-auto}"
QEMU_CPU="${SLOPTUNNEL_QEMU_CPU:-qemu64}"
QEMU_SMP="${SLOPTUNNEL_QEMU_SMP:-2}"
QEMU_MEM="${SLOPTUNNEL_QEMU_MEM:-4096}"
REUSE_DISK="${SLOPTUNNEL_WINDOWS_REUSE_DISK:-0}"

need_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "run as root so the lab can create namespaces, TAP devices, and firewall rules" >&2
    exit 1
  fi
}

cleanup() {
  set +e
  if [[ -n "${QEMU_PID:-}" ]]; then
    kill "$QEMU_PID" >/dev/null 2>&1
    wait "$QEMU_PID" >/dev/null 2>&1
  fi
  if [[ -n "${WAN_DHCP_PID:-}" ]]; then
    kill "$WAN_DHCP_PID" >/dev/null 2>&1
    wait "$WAN_DHCP_PID" >/dev/null 2>&1
  fi
  if [[ -n "${DNSMASQ_PID:-}" ]]; then
    kill "$DNSMASQ_PID" >/dev/null 2>&1
    wait "$DNSMASQ_PID" >/dev/null 2>&1
  fi
  if [[ -n "${HOST_DEV:-}" ]]; then
    iptables -t nat -D POSTROUTING -s 10.211.0.0/24 -o "$HOST_DEV" -j MASQUERADE >/dev/null 2>&1
    iptables -D FORWARD -i sic-wan-h -o "$HOST_DEV" -j ACCEPT >/dev/null 2>&1
    iptables -D FORWARD -i "$HOST_DEV" -o sic-wan-h -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1
  fi
  ip netns del "$LAN_NS" >/dev/null 2>&1
  ip netns del "$WIN_NS" >/dev/null 2>&1
  ip netns del "$FW_NS" >/dev/null 2>&1
  ip link del sic-wan-h >/dev/null 2>&1
  rm -rf "/etc/netns/$LAN_NS"
}
trap cleanup EXIT

wait_for_file() {
  local file="$1"
  local seconds="$2"
  local i
  for i in $(seq 1 "$seconds"); do
    [[ -r "$file" ]] && return 0
    sleep 1
  done
  return 1
}

need_root

for cmd in ip iptables dnsmasq qemu-img qemu-system-x86_64 timeout xorriso curl dig nc; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "missing required command: $cmd" >&2
    exit 1
  }
done
if [[ ! -r "$ISO" ]]; then
  echo "missing Windows Server ISO: $ISO" >&2
  exit 1
fi
if [[ ! -r "$TOKEN_FILE" ]]; then
  echo "missing token file: $TOKEN_FILE" >&2
  exit 1
fi
if [[ ! -r "$ROOT_DIR/build/sloptunnel.exe" ]]; then
  echo "missing Windows executable; build build/sloptunnel.exe first" >&2
  exit 1
fi

mkdir -p "$LAB_DIR" "$RESULTS"
if [[ -d "$BASE_LAB_DIR/deps" ]]; then
  mkdir -p "$LAB_DIR/deps"
  cp -f "$BASE_LAB_DIR/deps/"* "$LAB_DIR/deps/" 2>/dev/null || true
fi
SLOPTUNNEL_WINDOWS_LAB_DIR="$LAB_DIR" \
SLOPTUNNEL_WINDOWS_ISO="$ISO" \
SLOPTUNNEL_TOKEN_FILE="$TOKEN_FILE" \
  "$ROOT_DIR/scripts/windows_lab/make_answer_iso.sh"
cp "$ROOT_DIR/scripts/windows_lab/ics-sloptunnel-test.ps1" "$ANSWER_DIR/run-sloptunnel-test.ps1"
cp "$ROOT_DIR/scripts/windows_lab/ics-sloptunnel-test.ps1" "$ANSWER_DIR/\$OEM\$/\$\$/Setup/Scripts/run-sloptunnel-test.ps1"
xorriso -as mkisofs -quiet -J -r -o "$ANSWER_ISO" "$ANSWER_DIR"

printf 'sloptunnel windows ICS results\n' > "$RESULTS/SLOPTUNNEL_RESULTS.txt"
rm -f "$RESULTS"/*.txt "$RESULTS"/*.out "$RESULTS"/*.err
printf 'sloptunnel windows ICS results\n' > "$RESULTS/SLOPTUNNEL_RESULTS.txt"
rm -f "$MONITOR" "$VNC_SOCKET"
if [[ "$REUSE_DISK" == "1" && -f "$DISK" ]]; then
  echo "reusing existing Windows ICS disk: $DISK"
  BOOT_ARGS=(-boot order=c,menu=off)
else
  rm -f "$DISK"
  qemu-img create -f qcow2 "$DISK" 32G >/dev/null
  BOOT_ARGS=(-boot once=d,order=c,menu=off)
fi

HOST_DEV="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
if [[ -z "$HOST_DEV" ]]; then
  echo "could not detect host egress interface" >&2
  exit 1
fi

cleanup
trap cleanup EXIT

ip netns add "$WIN_NS"
ip netns add "$FW_NS"
ip netns add "$LAN_NS"

ip link add sic-fw-c type veth peer name sic-fw-f
ip link set sic-fw-c netns "$WIN_NS"
ip link set sic-fw-f netns "$FW_NS"

ip link add sic-wan-h type veth peer name sic-wan-f
ip link set sic-wan-f netns "$FW_NS"
ip addr add 10.211.0.1/24 dev sic-wan-h
ip link set sic-wan-h up

ip netns exec "$WIN_NS" ip link set lo up
ip netns exec "$WIN_NS" ip link add sic-wan-br type bridge
ip netns exec "$WIN_NS" ip link set sic-wan-br up
ip netns exec "$WIN_NS" ip addr add 10.210.0.2/24 dev sic-wan-br
ip netns exec "$WIN_NS" ip link set sic-fw-c master sic-wan-br
ip netns exec "$WIN_NS" ip link set sic-fw-c up
ip netns exec "$WIN_NS" ip tuntap add dev sic-wan-tap mode tap
ip netns exec "$WIN_NS" ip link set sic-wan-tap master sic-wan-br
ip netns exec "$WIN_NS" ip link set sic-wan-tap up
ip netns exec "$WIN_NS" ip link add sic-lan-br type bridge
ip netns exec "$WIN_NS" ip link set sic-lan-br up
ip netns exec "$WIN_NS" ip tuntap add dev sic-lan-tap mode tap
ip netns exec "$WIN_NS" ip link set sic-lan-tap master sic-lan-br
ip netns exec "$WIN_NS" ip link set sic-lan-tap up

ip link add sic-lan-w type veth peer name sic-lan-c
ip link set sic-lan-w netns "$WIN_NS"
ip link set sic-lan-c netns "$LAN_NS"
ip netns exec "$WIN_NS" ip link set sic-lan-w master sic-lan-br
ip netns exec "$WIN_NS" ip link set sic-lan-w up
ip netns exec "$LAN_NS" ip link set lo up
ip netns exec "$LAN_NS" ip addr add 192.168.137.2/24 dev sic-lan-c
ip netns exec "$LAN_NS" ip link set sic-lan-c up
ip netns exec "$LAN_NS" ip route add default via 192.168.137.1
mkdir -p "/etc/netns/$LAN_NS"
printf 'nameserver 1.1.1.1\n' > "/etc/netns/$LAN_NS/resolv.conf"

ip netns exec "$FW_NS" ip link set lo up
ip netns exec "$FW_NS" ip addr add 10.210.0.1/24 dev sic-fw-f
ip netns exec "$FW_NS" ip link set sic-fw-f up
ip netns exec "$FW_NS" ip addr add 10.211.0.2/24 dev sic-wan-f
ip netns exec "$FW_NS" ip link set sic-wan-f up
ip netns exec "$FW_NS" ip route add default via 10.211.0.1

sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$FW_NS" sysctl -w net.ipv4.ip_forward=1 >/dev/null
iptables -t nat -C POSTROUTING -s 10.211.0.0/24 -o "$HOST_DEV" -j MASQUERADE >/dev/null 2>&1 ||
  iptables -t nat -A POSTROUTING -s 10.211.0.0/24 -o "$HOST_DEV" -j MASQUERADE
iptables -C FORWARD -i sic-wan-h -o "$HOST_DEV" -j ACCEPT >/dev/null 2>&1 ||
  iptables -A FORWARD -i sic-wan-h -o "$HOST_DEV" -j ACCEPT
iptables -C FORWARD -i "$HOST_DEV" -o sic-wan-h -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 ||
  iptables -A FORWARD -i "$HOST_DEV" -o sic-wan-h -m state --state RELATED,ESTABLISHED -j ACCEPT

ip netns exec "$FW_NS" iptables -P INPUT DROP
ip netns exec "$FW_NS" iptables -P OUTPUT DROP
ip netns exec "$FW_NS" iptables -P FORWARD DROP
ip netns exec "$FW_NS" iptables -A INPUT -i lo -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -o lo -j ACCEPT
ip netns exec "$FW_NS" iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec "$FW_NS" iptables -A INPUT -i sic-fw-f -p udp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A INPUT -i sic-fw-f -p tcp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -o sic-wan-f -p udp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -o sic-wan-f -p tcp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec "$FW_NS" iptables -A FORWARD -i sic-fw-f -o sic-wan-f -p tcp --dport "$TCP_PORT" -j ACCEPT
ip netns exec "$FW_NS" iptables -t nat -A POSTROUTING -s 10.210.0.0/24 -o sic-wan-f -j MASQUERADE

DNSMASQ_LOG="$LAB_DIR/ics-dnsmasq.log"
WAN_DHCP_LOG="$LAB_DIR/ics-wan-dhcp.log"
rm -f "$DNSMASQ_LOG" "$WAN_DHCP_LOG"
ip netns exec "$FW_NS" dnsmasq --no-daemon --no-hosts --no-resolv \
  --listen-address=10.210.0.1 --bind-interfaces --server="/$DNS_DOMAIN/$SERVER_IP" \
  --log-queries --log-facility=- > "$DNSMASQ_LOG" 2>&1 &
DNSMASQ_PID="$!"
ip netns exec "$WIN_NS" dnsmasq --no-daemon --no-hosts --no-resolv --port=0 \
  --interface=sic-wan-br --bind-interfaces \
  --dhcp-range=10.210.0.50,10.210.0.80,255.255.255.0,1h \
  --dhcp-option=option:router,10.210.0.1 \
  --dhcp-option=option:dns-server,10.210.0.1 \
  --log-dhcp --log-facility=- > "$WAN_DHCP_LOG" 2>&1 &
WAN_DHCP_PID="$!"
sleep 1

if [[ "$QEMU_ACCEL" == "auto" ]]; then
  if [[ -r /dev/kvm && -w /dev/kvm ]]; then
    QEMU_ACCEL="kvm"
    QEMU_CPU="${SLOPTUNNEL_QEMU_CPU:-host}"
  else
    QEMU_ACCEL="tcg"
  fi
fi
case "$QEMU_ACCEL" in
  kvm) QEMU_ACCEL_ARGS=(-accel kvm) ;;
  tcg) QEMU_ACCEL_ARGS=(-accel tcg,thread=multi) ;;
  *) echo "invalid SLOPTUNNEL_QEMU_ACCEL: $QEMU_ACCEL" >&2; exit 1 ;;
esac

echo "starting two-NIC Windows ICS lab using $QEMU_ACCEL; timeout ${QEMU_TIMEOUT}s"
QEMU_ARGS=(
  "${QEMU_ACCEL_ARGS[@]}"
  -cpu "$QEMU_CPU"
  -smp "$QEMU_SMP"
  -m "$QEMU_MEM"
  -display none
  -vnc "unix:$VNC_SOCKET"
  -monitor "unix:$MONITOR,server=on,wait=off"
  -serial "file:$LAB_DIR/ics-serial.log"
  -drive "file=$DISK,if=ide,index=0,media=disk,format=qcow2"
  -drive "file=$ISO,if=ide,index=1,media=cdrom,readonly=on"
  -drive "file=$ANSWER_ISO,if=ide,index=2,media=cdrom,readonly=on"
  -drive "file=fat:rw:$RESULTS,if=ide,index=3,media=disk,format=raw"
  -netdev tap,id=wan,ifname=sic-wan-tap,script=no,downscript=no
  -device e1000,netdev=wan,mac=52:54:00:12:34:56
  -netdev tap,id=lan,ifname=sic-lan-tap,script=no,downscript=no
  -device e1000,netdev=lan,mac=52:54:00:65:43:21
  "${BOOT_ARGS[@]}"
)
ip netns exec "$WIN_NS" timeout "$QEMU_TIMEOUT" qemu-system-x86_64 "${QEMU_ARGS[@]}" &
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

if wait_for_file "$RESULTS/ICS_READY.txt" 3600; then
  echo "ICS/WinNAT private side ready; checking LAN client preflight"
  ip netns exec "$LAN_NS" ping -c 2 -W 3 192.168.137.1 || true
  if ip netns exec "$LAN_NS" timeout 8 curl -4 -fsS --max-time 6 http://1.1.1.1/cdn-cgi/trace >/tmp/slop-ics-preflight.txt 2>&1; then
    echo "unexpected: LAN client direct HTTP escaped before tunnel" | tee "$RESULTS/lan-preflight.txt"
    cat /tmp/slop-ics-preflight.txt | tee -a "$RESULTS/lan-preflight.txt"
  else
    echo "LAN client direct HTTP blocked before tunnel" | tee "$RESULTS/lan-preflight.txt"
    cat /tmp/slop-ics-preflight.txt >> "$RESULTS/lan-preflight.txt" || true
  fi
else
  echo "Windows guest did not report ICS_READY" >&2
fi

if wait_for_file "$RESULTS/TUNNEL_READY.txt" 240; then
  echo "tunnel ready; driving LAN client traffic through Windows sharing"
  {
    echo "LAN client route:"
    ip netns exec "$LAN_NS" ip route
    echo "LAN HTTP through Windows sharing while sloptunnel is active:"
    ip netns exec "$LAN_NS" timeout 60 curl -4 -m 45 http://1.1.1.1/cdn-cgi/trace
    echo "lan_http_exit=$?"
  } > "$RESULTS/lan-tunnel.txt" 2>&1 || true
  for _ in $(seq 1 20); do
    ip netns exec "$LAN_NS" timeout 5 curl -4 -fsS --max-time 4 http://1.1.1.1/cdn-cgi/trace >/dev/null 2>&1 || true
    sleep 1
  done
else
  echo "Windows guest did not report TUNNEL_READY" >&2
fi

while kill -0 "$QEMU_PID" >/dev/null 2>&1; do
  [[ -r "$RESULTS/DONE.txt" || -r "$RESULTS/done.txt" ]] && break
  sleep 10
done
wait "$QEMU_PID" || true
QEMU_PID=""

echo "ICS lab result tail:"
tail -120 "$RESULTS/ics-result.txt" 2>/dev/null || true
echo "LAN tunnel result:"
cat "$RESULTS/lan-tunnel.txt" 2>/dev/null || true
echo "DNS TXT sample:"
awk '/query\[TXT\]/ { print substr($0, 1, 220); count++; if (count == 5) exit }' "$DNSMASQ_LOG" || true

grep -q 'query\[TXT\]' "$DNSMASQ_LOG" || {
  echo "no DNS TXT tunnel queries were observed" >&2
  exit 1
}
