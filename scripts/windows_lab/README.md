# Windows Server Lab

This lab boots an official Microsoft Windows Server evaluation ISO under QEMU,
installs Server Core with an unattended answer ISO, then runs `sloptunnel.exe`
inside the guest.

The Windows NIC is attached to a TAP device bridged inside a Linux client
namespace behind a firewall namespace. The firewall blocks outbound traffic
except:

- TCP `5223`
- DNS on port `53`

The guest test writes results to `lab/windows/results/` through a QEMU FAT share.
Large downloaded/generated files under `lab/windows/` are gitignored.

## Prerequisites

```sh
apt-get install -y qemu-system-x86 qemu-utils ovmf wimtools dos2unix xorriso dnsmasq iptables
```

Download the official Windows Server 2022 Evaluation ISO:

```sh
mkdir -p lab/windows
curl -L -o lab/windows/SERVER_EVAL_x64FRE_en-us.iso \
  'https://go.microsoft.com/fwlink/p/?LinkID=2195280&clcid=0x409&culture=en-us&country=US'
```

For full-tunnel mode, place `wintun.dll` at:

```text
lab/windows/deps/wintun.dll
```

## Run

Build `sloptunnel.exe`, create the answer ISO, then launch the VM:

```sh
x86_64-w64-mingw32-gcc -std=c11 -Wall -Wextra -O2 -o build/sloptunnel.exe src/sloptunnel.c -lws2_32
scripts/windows_lab/make_answer_iso.sh
scripts/windows_lab/run_windows_server_lab.sh
```

There is no KVM dependency, but without `/dev/kvm` the install runs under QEMU
TCG and can take a long time.
