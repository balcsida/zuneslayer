# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Zuneslayer is an exploit suite for Microsoft Zune portable media players (2006-2011). The goal is archival preservation of encrypted Zune applications by achieving kernel code execution without triggering the hardware crypto key wipe that occurs when XNA dev apps run.

Two device families are targeted:
- **Zune HD** (`ZuneHD/`) — Nvidia Tegra APX 2600 (ARM1176), Windows CE 6.0, firmware v4.5
- **Zune SD** (`ZuneSD/`) — Freescale i.MX31L, Windows CE 5.5 (Zune 30/80/120/4/8/16)

## Build Systems

### Rust (zuneslayer_debug, httpserv, tools)

```bash
# Debug client — connects to Zune HD over TCP
cd ZuneHD/zuneslayer_debug && cargo build --release

# HTTP server — serves browser exploit pages to Zune browser
cd ZuneHD/httpserv && cargo build --release

# ROM extraction tools (requires Wine for eimgfs)
cd tools && cargo build --release
```

Requires Rust nightly. The debug client uses prost-build to compile `src/protocol/msg.proto` at build time.

### C++ native payload (nativeapp)

Built with **Visual Studio 2008** + **OpenZDK** (ARM Windows CE cross-compiler). Open `ZuneHD/zuneslayer_kernel/template/apptemplate.sln`, build the `nativeapp` project for `OpenZDK (ARMV4I)`. The post-build step copies the binary into `exploiter/Content/nativeapp.exe`.

### C# XNA exploiter

Part of the same `apptemplate.sln`. Targets XNA Game Studio 3.1 for Zune. Deploy to device via Visual Studio's XNA deployment (requires Zune desktop software + USB connection).

## Exploit Chain Architecture

```
1. Deploy XNA exploiter via VS → copies nativeapp.exe to device
2. XNA app runs → kernel escalation via IOCTL driver bug
3. nativeapp copies itself to \Flash2\payload.exe
4. Browser exploit (orig.html via httpserv) → CVE-2019-1367 UAF in IE6
5. ROP chain calls CreateProcessW("\Flash2\payload.exe")
6. nativeapp starts TCP server on 0.0.0.0:1337
7. zuneslayer_debug connects over WiFi to interact
```

The XNA app must be launched at least once after each rebuild to copy the updated binary to `\Flash2\payload.exe`. The browser exploit always runs the `\Flash2\` copy, not the XNA content directory copy.

## Device Communication Protocol

nativeapp runs a binary TCP protocol on port 1337. Each command is a 32-byte packet with command ID in byte 0:

| Cmd | Function | Notes |
|-----|----------|-------|
| 1 | kread_u32(addr) | Kernel memory read via GetFSHeapInfo gadget |
| 2 | OpenProcess | |
| 3 | ReadProcessMemory | |
| 4 | WriteProcessMemory | |
| 15 | Physical memory dump | NKCreateStaticMapping + byte-by-byte read |
| 16 | Protobuf commands | LSDIR, RDFILE (uses nanopb on device, prost on PC) |
| 17 | Uncached I/O read | NKCreateStaticMapping (currently broken — hangs) |
| 20 | kwrite_u32(addr, val) | Kernel write via kwr gadget |
| 21 | IROM dump | Page-by-page NKCreateStaticMapping |
| 22 | Block device probe | For BCT reading/corruption |

## Key Technical Details

### Kernel Gadgets (nativeapp)
- **kwr(addr, val)**: Creates a thread that calls `ExitThread(val)`, then `GetExitCodeThread(thread, addr)` writes val to addr. Works for any kernel VA.
- **kreadb(addr)**: Redirects `GetFSHeapInfo` function pointer at `0x80060da0` to gadget at `0x80015020`, calls it with magic `0x1338` (read) or `0x1337` (write).
- **NKCreateStaticMapping**: Redirects `GetFSHeapInfo` to `0x80069de0`, calls to map physical addresses to kernel VAs.

### Memory Map (from OEMAddressTable in NK.bin)
Only **uncached** VAs (`0xBFxxxxxx`) are mapped in the page table. Cached VAs (`0x9Fxxxxxx`) are FAULT.

| Physical | Uncached VA | Description |
|----------|------------|-------------|
| 0x60000000 | 0xBF600000 | AHB / CLK_RST / Secure Boot |
| 0x70000000 | 0xBF700000 | Fuse / PMC (crashes on access — clock off) |
| 0xFFF00000 | 0xBFF00000 | IROM (Boot ROM) — only page 0 readable |
| 0x40000000 | 0xBF400000 | IRAM |

### IROM Protection
- `SB_CSR_0` at PA `0x6000C200`: `PIROM_DISABLE=1` (sticky bit, cannot be software-cleared)
- First 4KB page readable via NKCreateStaticMapping, pages 1-15 cause data abort
- Boot ROM identified as "NV Boot AP15.0001" (Tegra APX 2600)
- Full dump requires Fusée Gelée (pre-boot USB RCM exploit, CVE-2018-6242)
- Zune HD in APX mode: USB `VID_0955 PID_7416`

### USB Networking
The Zune uses IP-over-MTPZ (not standard RNDIS). Device=`192.168.55.101`, PC=`192.168.55.100`. **One-directional**: device can connect OUT to PC, but PC cannot connect IN. USB cable disables WiFi. See `ZuneHD/docs/usb-networking.md`.

## Common Pitfalls

- **sprintf buffer overflow**: The `getIpAddress()` buffer in main.cpp is 128 bytes. Adding format strings can overflow it — always check size.
- **`hax()` never returns**: It calls `Server()` which loops in `accept()`. Any code after `hax()` in `wWinMain` will never execute.
- **Fuse controller crashes**: Reading PA `0x7000F800` (VA `0xBF70F800`) causes a data abort — the fuse clock is not enabled.
- **BSEV vs BSEA**: BSEV (video) is at PA `0x6001B000`, BSEA (audio) is at `0x60011000`. The addresses were confused in early code.
