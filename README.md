# sloptunnel

`sloptunnel` is a minimal C TUI for experimenting with a multi-port tunnel transport.
It builds as one executable that can run as either a client or a server.

Current implementation:

- ANSI color TUI with arrow-key selection.
- Headless server/client mode for remote hosts.
- UDP and TCP auto-discovery transports. The default mode scans/listens across a
  range instead of assuming fixed ports.
- Packet framing with a shared-token validation tag.
- Round-robin client transmit balancing across all discovered ports.
- Live status: server IP, active mode, selected ports, per-port bandwidth, packet counts, RTT.

This first cut is a transport prototype, not a production VPN. It does not yet create
TUN/TAP interfaces, change system routes, NAT packets, or encrypt payload contents.
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

## TUI

```sh
./build/sloptunnel
```

Use the up/down arrows to select a setting and `Enter` to edit or toggle it.
Press `q` to quit.

## Headless server

```sh
./build/sloptunnel --server --transport both --ports auto --token "replace-me" --headless
```

For long-running servers, prefer a token file so the secret is not visible in the
process command line:

```sh
./build/sloptunnel --server --transport both --ports auto --token-file /path/to/token --headless
```

## Headless client

```sh
./build/sloptunnel --client --server-ip 18.219.84.252 --transport both --ports auto --token "replace-me" --rate-mbps 8 --headless
```

You can constrain auto mode when needed:

```sh
./build/sloptunnel --server --transport tcp --ports auto:1-1024 --headless
./build/sloptunnel --server --transport both --ports auto:1024-65535 --max-auto-ports 4096 --headless
```

The EC2 security group and host firewall must allow inbound UDP/TCP for the ports the
server binds. Binding common TCP ports like `80` and `443` requires root/admin
permission and will fail if another service already owns those ports.

## Deploy to EC2

The helper script expects the provided EC2 key at `keys/sloptunnel-ec2.pem`:

```sh
SLOPTUNNEL_TOKEN="replace-me" scripts/deploy_ec2.sh
```

It builds locally, copies the executable to `/home/ubuntu/sloptunnel/`, and starts a
headless server with `nohup`. By default the helper starts the EC2 listener through
`sudo` so it can bind privileged ports; set `SLOPTUNNEL_USE_SUDO=0` to keep it under
the `ubuntu` user.

Deploy defaults to `SLOPTUNNEL_TRANSPORT=both` and `SLOPTUNNEL_PORTS=auto`.
The helper copies the token into `/home/ubuntu/sloptunnel/token` and starts the
server with `--token-file`.
