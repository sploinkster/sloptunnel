# sloptunnel

`sloptunnel` is a minimal C TUI for a routed multi-port tunnel. It builds as one
executable that can run as either a client or a server.

Current implementation:

- ANSI color TUI with arrow-key selection.
- Headless server/client mode for remote hosts.
- UDP, TCP, and DNS transports. The default `all` mode can stack every available
  method and scans/listens across a range instead of assuming fixed ports.
- Proper DNS tunnel mode: client frames are encoded into DNS TXT queries under a
  configured domain, and server replies are returned as TXT answers on UDP/53.
- Full-tunnel IPv4 mode using TUN/Wintun. Client traffic is routed through the
  tunnel while the transport socket keeps a host route to the server.
- Optional tunneled IPv6 addressing/routes with `--ipv6`.
- Linux server NAT/forwarding setup for EC2 egress.
- Packet framing with a shared-token validation tag.
- Round-robin client transmit balancing across all discovered ports.
- Live status: server IP, active mode, selected ports, transport bandwidth,
  TUN bandwidth, packet counts, RTT, drops, and peer count.

This is not a hardened production VPN yet. The shared token authenticates frames,
but payload encryption is not implemented in this codebase.
The server can try to bind the full requested UDP/TCP port range with `--ports auto`; how much it
actually covers depends on OS privileges, file descriptor limits, ports already in
use, and cloud/security-group firewall rules. A user-space process still needs real
sockets, so there is no truly portless mode.

TCP listeners use the same authenticated frame format. If ordinary HTTP/TLS traffic
hits a masqueraded listener such as `80` or `443`, the connection is closed unless it
sends a valid sloptunnel frame.

## Build

Linux:

```sh
make
```

Windows with MinGW:

```sh
mingw32-make
```

Windows full-tunnel mode requires Administrator privileges and `wintun.dll` next to
`sloptunnel.exe`. The DLL is distributed by the WireGuard/Wintun project.

## TUI

```sh
./build/sloptunnel
```

Use the up/down arrows to select a setting and `Enter` to edit or toggle it.
Press `q` to quit.

## Headless server

```sh
./build/sloptunnel --server --transport all --ports auto --token "replace-me" --headless
```

For long-running servers, prefer a token file so the secret is not visible in the
process command line:

```sh
./build/sloptunnel --server --transport all --ports auto --token-file /path/to/token --headless
```

## Headless client

```sh
./build/sloptunnel --client --server-ip 18.219.84.252 --transport all --ports auto --token "replace-me" --rate-mbps 8 --headless
```

By default the client installs full-tunnel IPv4 routes. Website browsing, DNS, and
other IPv4 traffic are routed through the TUN interface once the client is running.
Use `--no-vpn` for transport benchmarking only, or `--no-route` to create the TUN
interface without capturing the default route.

On Windows hosts that also share Internet Connection Sharing to an Ethernet/AP
side, leave the tunnel egress setting on `auto` first. If paths authenticate and
then drop as soon as the shared Ethernet/AP side is connected, force the upstream
adapter so the server and DNS bypass routes stay on Wi-Fi:

```sh
sloptunnel.exe --client --server-ip 18.219.84.252 --egress-interface Wi-Fi --token-file sloptunnel-token.txt
```

DNS tunneling can be used alone or stacked with port masquerading:

```sh
./build/sloptunnel --server --transport dns --dns-tunnel-domain sploinkstersploinkster.online --token-file /path/to/token --headless
./build/sloptunnel --client --server-ip 18.219.84.252 --transport tcp+dns --ports 5223 --dns-tunnel-domain sploinkstersploinkster.online --token-file /path/to/token --headless
```

`--dns-resolver` controls where the client sends DNS tunnel queries. It defaults to
the server IP, which is useful when the authoritative DNS host is reachable
directly. Point it at a recursive resolver when testing delegation through normal
DNS resolution.

You can constrain auto mode when needed:

```sh
./build/sloptunnel --server --transport tcp --ports auto:1-1024 --headless
./build/sloptunnel --server --transport all --ports auto:1024-65535 --max-auto-ports 4096 --headless
```

The EC2 security group and host firewall must allow inbound UDP/TCP for the ports the
server binds. Binding common TCP ports like `80` and `443` requires root/admin
permission and will fail if another service already owns those ports.

Linux server mode creates `sloptun0` at `10.44.0.1/24`, enables IPv4 forwarding, and
adds iptables MASQUERADE/FORWARD rules for `10.44.0.0/24`. The client uses
`10.44.0.2/24`. Override these with `--tun-name`, `--tun-server-ip`,
`--tun-client-ip`, `--tun-cidr`, and `--tun-mtu`.

With `--ipv6`, server/client addresses default to `fd44:534c:4f50::1/64` and
`fd44:534c:4f50::2/64`. Linux server mode enables IPv6 forwarding and attempts
ip6tables NAT/forwarding rules when `ip6tables` is present; client mode installs
split IPv6 default routes over the tunnel. Override these with `--tun-server-ip6`,
`--tun-client-ip6`, and `--tun-cidr6`.

## Deploy to EC2

The helper script expects the provided EC2 key at `keys/sloptunnel-ec2.pem`:

```sh
SLOPTUNNEL_TOKEN="replace-me" scripts/deploy_ec2.sh
```

It builds locally, copies the executable to `/home/ubuntu/sloptunnel/`, and starts a
headless server with `nohup`. By default the helper starts the EC2 listener through
`sudo` so it can bind privileged ports; set `SLOPTUNNEL_USE_SUDO=0` to keep it under
the `ubuntu` user.

Deploy defaults to `SLOPTUNNEL_TRANSPORT=all`, `SLOPTUNNEL_PORTS=auto`, and
`SLOPTUNNEL_DNS_DOMAIN=sploinkstersploinkster.online`.
The helper copies the token into `/home/ubuntu/sloptunnel/token` and starts the
server with `--token-file`.
