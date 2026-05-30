#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_NS="${SLOPTUNNEL_LAB_CLIENT_NS:-slop-client}"
FW_NS="${SLOPTUNNEL_LAB_FW_NS:-slop-fw}"
SERVER_IP="${SLOPTUNNEL_SERVER_IP:-18.219.84.252}"
DNS_DOMAIN="${SLOPTUNNEL_DNS_DOMAIN:-sploinkstersploinkster.online}"
TCP_PORT="${SLOPTUNNEL_TCP_PORT:-5223}"
TOKEN_FILE="${SLOPTUNNEL_TOKEN_FILE:-/tmp/sloptunnel_token}"
CLIENT_LOG="${SLOPTUNNEL_LAB_CLIENT_LOG:-/tmp/sloptunnel-lab-client.log}"
DNSMASQ_LOG="${SLOPTUNNEL_LAB_DNSMASQ_LOG:-/tmp/sloptunnel-lab-dnsmasq.log}"
CLIENT_PID=""
DNSMASQ_PID=""

need_root() {
  if [[ "$(id -u)" != "0" ]]; then
    echo "run as root so the lab can create namespaces, TUN devices, and firewall rules" >&2
    exit 1
  fi
}

cleanup() {
  set +e
  if [[ -n "$CLIENT_PID" ]]; then
    kill "$CLIENT_PID" >/dev/null 2>&1
    wait "$CLIENT_PID" >/dev/null 2>&1
  fi
  if [[ -n "$DNSMASQ_PID" ]]; then
    kill "$DNSMASQ_PID" >/dev/null 2>&1
    wait "$DNSMASQ_PID" >/dev/null 2>&1
  fi
  if [[ -n "${HOST_DEV:-}" ]]; then
    iptables -t nat -D POSTROUTING -s 10.201.0.0/24 -o "$HOST_DEV" -j MASQUERADE >/dev/null 2>&1
    iptables -D FORWARD -i stwan-h -o "$HOST_DEV" -j ACCEPT >/dev/null 2>&1
    iptables -D FORWARD -i "$HOST_DEV" -o stwan-h -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1
  fi
  ip netns del "$CLIENT_NS" >/dev/null 2>&1
  ip netns del "$FW_NS" >/dev/null 2>&1
  rm -rf "/etc/netns/$CLIENT_NS"
}
trap cleanup EXIT

need_root

for cmd in ip iptables dnsmasq curl dig ping timeout; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "missing required command: $cmd" >&2
    exit 1
  }
done

if [[ ! -r "$TOKEN_FILE" ]]; then
  echo "token file not readable: $TOKEN_FILE" >&2
  exit 1
fi

HOST_DEV="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')"
if [[ -z "$HOST_DEV" ]]; then
  echo "could not detect host egress interface" >&2
  exit 1
fi

make -C "$ROOT_DIR"

cleanup
trap cleanup EXIT

ip netns add "$CLIENT_NS"
ip netns add "$FW_NS"

ip link add stcli-c type veth peer name stcli-f
ip link set stcli-c netns "$CLIENT_NS"
ip link set stcli-f netns "$FW_NS"

ip link add stwan-h type veth peer name stwan-f
ip link set stwan-f netns "$FW_NS"

ip addr add 10.201.0.1/24 dev stwan-h
ip link set stwan-h up

ip netns exec "$CLIENT_NS" ip link set lo up
ip netns exec "$CLIENT_NS" ip addr add 10.200.0.2/24 dev stcli-c
ip netns exec "$CLIENT_NS" ip link set stcli-c up
ip netns exec "$CLIENT_NS" ip route add default via 10.200.0.1

ip netns exec "$FW_NS" ip link set lo up
ip netns exec "$FW_NS" ip addr add 10.200.0.1/24 dev stcli-f
ip netns exec "$FW_NS" ip link set stcli-f up
ip netns exec "$FW_NS" ip addr add 10.201.0.2/24 dev stwan-f
ip netns exec "$FW_NS" ip link set stwan-f up
ip netns exec "$FW_NS" ip route add default via 10.201.0.1

mkdir -p "/etc/netns/$CLIENT_NS"
printf 'nameserver 1.1.1.1\n' > "/etc/netns/$CLIENT_NS/resolv.conf"

sysctl -w net.ipv4.ip_forward=1 >/dev/null
ip netns exec "$FW_NS" sysctl -w net.ipv4.ip_forward=1 >/dev/null

iptables -t nat -C POSTROUTING -s 10.201.0.0/24 -o "$HOST_DEV" -j MASQUERADE >/dev/null 2>&1 ||
  iptables -t nat -A POSTROUTING -s 10.201.0.0/24 -o "$HOST_DEV" -j MASQUERADE
iptables -C FORWARD -i stwan-h -o "$HOST_DEV" -j ACCEPT >/dev/null 2>&1 ||
  iptables -A FORWARD -i stwan-h -o "$HOST_DEV" -j ACCEPT
iptables -C FORWARD -i "$HOST_DEV" -o stwan-h -m state --state RELATED,ESTABLISHED -j ACCEPT >/dev/null 2>&1 ||
  iptables -A FORWARD -i "$HOST_DEV" -o stwan-h -m state --state RELATED,ESTABLISHED -j ACCEPT

ip netns exec "$FW_NS" iptables -P INPUT DROP
ip netns exec "$FW_NS" iptables -P OUTPUT DROP
ip netns exec "$FW_NS" iptables -P FORWARD DROP
ip netns exec "$FW_NS" iptables -A INPUT -i lo -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -o lo -j ACCEPT
ip netns exec "$FW_NS" iptables -A INPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec "$FW_NS" iptables -A INPUT -i stcli-f -p udp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A INPUT -i stcli-f -p tcp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -o stwan-f -p udp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A OUTPUT -o stwan-f -p tcp --dport 53 -j ACCEPT
ip netns exec "$FW_NS" iptables -A FORWARD -m state --state RELATED,ESTABLISHED -j ACCEPT
ip netns exec "$FW_NS" iptables -A FORWARD -i stcli-f -o stwan-f -p tcp --dport "$TCP_PORT" -j ACCEPT
ip netns exec "$FW_NS" iptables -t nat -A POSTROUTING -s 10.200.0.0/24 -o stwan-f -j MASQUERADE

rm -f "$CLIENT_LOG" "$DNSMASQ_LOG"
ip netns exec "$FW_NS" dnsmasq --no-daemon --no-hosts --no-resolv \
  --listen-address=10.200.0.1 --bind-interfaces --server="/$DNS_DOMAIN/$SERVER_IP" \
  --log-queries --log-facility=- > "$DNSMASQ_LOG" 2>&1 &
DNSMASQ_PID="$!"
sleep 1

echo "preflight: direct HTTP from the client namespace should be blocked"
if ip netns exec "$CLIENT_NS" timeout 4 curl -4 -fsS --max-time 3 http://1.1.1.1/ >/dev/null 2>&1; then
  echo "unexpected: direct HTTP escaped the firewall" >&2
  exit 1
fi

echo "preflight: TCP/$TCP_PORT is allowed through the firewall"
ip netns exec "$CLIENT_NS" timeout 4 bash -c "</dev/tcp/$SERVER_IP/$TCP_PORT"

echo "preflight: DNS resolver forwards the tunnel domain"
if ! ip netns exec "$CLIENT_NS" timeout 5 dig @"10.200.0.1" "$DNS_DOMAIN" NS +time=2 +tries=1 +short; then
  echo "warning: NS lookup preflight timed out; the TXT tunnel query stream is checked below"
fi

echo "starting sloptunnel client behind firewall with tcp+dns"
ip netns exec "$CLIENT_NS" timeout 45 "$ROOT_DIR/build/sloptunnel" \
  --client --transport tcp+dns --ports "$TCP_PORT" --server-ip "$SERVER_IP" \
  --dns-tunnel-domain "$DNS_DOMAIN" --dns-resolver 10.200.0.1 \
  --token-file "$TOKEN_FILE" --tun-name sloplab0 --headless > "$CLIENT_LOG" 2>&1 &
CLIENT_PID="$!"

sleep 8
grep -q "paths=2/2" "$CLIENT_LOG" || {
  tail -40 "$CLIENT_LOG" >&2
  echo "client did not authenticate both TCP and DNS paths" >&2
  exit 1
}

echo "test: tunnel gateway ping"
if ! ip netns exec "$CLIENT_NS" ping -c 3 -W 3 10.44.0.1; then
  echo "warning: ICMP to the tunnel gateway did not return during the short lab window"
fi

echo "test: HTTP over captured full-tunnel route"
ip netns exec "$CLIENT_NS" timeout 15 curl -4 -fsS --max-time 12 http://1.1.1.1/cdn-cgi/trace | head -8

grep -q 'query\[TXT\]' "$DNSMASQ_LOG" || {
  tail -40 "$DNSMASQ_LOG" >&2
  echo "no DNS TXT tunnel queries reached the firewall resolver" >&2
  exit 1
}

echo "dns tunnel query log sample:"
grep 'query\[TXT\]' "$DNSMASQ_LOG" | head -3 | cut -c1-220 || true

echo "client log tail:"
tail -12 "$CLIENT_LOG"
