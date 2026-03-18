# Tegra APX 2600 Register Map — Zune HD

Extracted from Zune HD v4.5 firmware (PavoBaseline.cab):
- `ZBoot.bin` (662,995 bytes) — bootloader, build path `E:\pyxis\v4.5\PLATFORM\wookie\src\bootloader\zboot\usb.c`
- `NK.bin` (11,992,363 bytes) — Windows CE 6.0 kernel image

Chip identification strings in NK.bin: "APX 2500", "Tegra APX 2600", "APX 2600", "Tegra APX 2300", "Tegra 600", "Tegra 650"

## OEMAddressTable

Located at NK.bin offset `0x39B2F` and ZBoot.bin offset `0x70A6F`. Identical in both images. 14 entries.

Windows CE maps each physical region into two virtual address ranges:
- **Cached**: `0x9Fxxxxxx` (currently faults — not wired in page table)
- **Uncached**: `0xBFxxxxxx` (functional, used by nativeapp gadgets)

| # | Physical Addr | Cached VA | Uncached VA | Size | Description |
|---|---------------|-----------|-------------|------|-------------|
| 0 | 0x00000000 | 0x80000000 | 0xA0000000 | 128 MB | SDRAM |
| 1 | 0x58000000 | 0x9E000000 | 0xBE000000 | 16 MB | External memory |
| 2 | 0x54000000 | 0x9F000000 | 0xBF000000 | 4 MB | Peripheral |
| 3 | 0x40000000 | 0x9F400000 | 0xBF400000 | 1 MB | IRAM (256 KB usable) |
| 4 | 0x50000000 | 0x9F500000 | 0xBF500000 | 1 MB | Peripheral |
| 5 | 0x60000000 | 0x9F600000 | 0xBF600000 | 1 MB | AHB / CLK_RST / Secure Boot |
| 6 | 0x70000000 | 0x9F700000 | 0xBF700000 | 1 MB | APB / Fuse / PMC |
| 7 | 0xB0000000 | 0x9F800000 | 0xBF800000 | 2 MB | Peripheral |
| 8 | 0xB8000000 | 0x9FA00000 | 0xBFA00000 | 2 MB | Peripheral |
| 9 | 0xC5000000 | 0x9FC00000 | 0xBFC00000 | 1 MB | USB controllers |
| 10 | 0xC8000000 | 0x9FD00000 | 0xBFD00000 | 1 MB | Peripheral |
| 11 | 0xC3000000 | 0x9FE00000 | 0xBFE00000 | 1 MB | Peripheral |
| 12 | 0xFFF00000 | 0x9FF00000 | 0xBFF00000 | 1 MB | IROM (Boot ROM) |
| 13 | 0x80000000 | 0x9DC00000 | 0xBDC00000 | 4 MB | External SDRAM |

## USB Controller

**The APX 2600 USB base is at PA `0xC5000000`, NOT `0x7D000000`.**

This was confirmed by the OEMAddressTable (entry 9) and device configuration tables in both ZBoot.bin and NK.bin. The `0x7D000000` address used by later Tegra chips (T20/T30) does not apply here.

Three USB controller instances exist:

| Instance | Physical Addr | Uncached VA | Size | Handler ID | Role |
|----------|---------------|-------------|------|------------|------|
| USB1 | 0xC5000000 | 0xBFC00000 | 16 KB | 0x4912 | SUSP / UTMIP PHY registers |
| USB2D | 0xC5004000 | 0xBFC04000 | 16 KB | 0x4913 | ChipIdea/EHCI device controller |
| USB3 | 0xC5008000 | 0xBFC08000 | 16 KB | 0x4914 | Additional controller |

### USB2D Register Offsets (ChipIdea/EHCI, base + offset)

Confirmed present in ZBoot.bin via ARM load/store instruction analysis:

| Offset | Register | Description |
|--------|----------|-------------|
| +0x140 | USBCMD | USB command |
| +0x144 | USBSTS | USB status |
| +0x148 | USBINTR | USB interrupt enable |
| +0x154 | DEVICEADDR | Device address |
| +0x158 | ENDPTLISTADDR | Endpoint list (QH) base address |
| +0x184 | PORTSC1 | Port status/control |
| +0x1A4 | OTGSC | OTG status/control |
| +0x1A8 | USBMODE | USB mode (device/host) |
| +0x1AC | ENDPTSETUPSTAT | Endpoint setup status |
| +0x1B0 | ENDPTPRIME | Endpoint prime |
| +0x1B4 | ENDPTFLUSH | Endpoint flush |
| +0x1B8 | ENDPTSTAT | Endpoint status |
| +0x1BC | ENDPTCOMPLETE | Endpoint complete |
| +0x1C0 | ENDPTCTRL0 | Endpoint 0 control |
| +0x1C4 | ENDPTCTRL1 | Endpoint 1 control |

### USB Descriptors

USB VID `0x0955` (NVIDIA) found in ZBoot descriptor structures at offsets `0x12748`, `0x12B28`, `0x13948`, `0x13D28`.

### USB Drivers in NK.bin

| DLL | Offset | Role |
|-----|--------|------|
| libnvusbf.dll | 0x631BF8 | NVIDIA USB Function driver (UFN_*) |
| MtpClientDrvUsb.dll | 0x8B7DBF | MTP over USB transport (MUT_*) |
| MtpClientDrvIp.dll | 0x89A70F | MTP over IP transport (MIT_*) |
| usbd.dll | 0x6820C7 | Standard WinCE USB host driver |

## IRAM Layout

| Address | Hits in ZBoot | Hits in NK | Role |
|---------|---------------|------------|------|
| 0x40000000 | 63 | 1219 | IRAM base (256 KB) |
| 0x40005000 | 3 | 4 | RCM DMA buffer 1 |
| 0x40009000 | 0 | 0 | **Not found** — DMA buffer 2 may differ from T210 |
| 0x40010000 | 3 | 14 | Payload start / stack boundary |
| 0x40020000 | 3 | 7 | Upper IRAM region |

The absence of `0x40009000` suggests the APX 2600 boot ROM may use different DMA buffer addresses than the T210. The second buffer location is unknown and would need to be determined from the full IROM dump or USB traffic analysis.

## Secure Boot Registers

| Register | Physical Addr | Uncached VA | Hits |
|----------|---------------|-------------|------|
| SB_CSR_0 | 0x6000C200 | 0xBF60C200 | 3 per binary |
| Fuse controller | 0x7000F800 | 0xBF70F800 | 3 per binary |

## BCT (Boot Configuration Table)

Three ECEC signatures found in ZBoot.bin:
- Offset `0x2B` — primary BCT in file header
- Offset `0x31C57` — secondary boot block
- Offset `0x6B2AB` — tertiary block

BCT-related strings in ZBoot: "erase the BCT" (0x3601), "over BCT" (0x3D84).

## Fusée Gelée Exploit Parameters (CVE-2018-6242)

Derived from TegraRcmSmash source code (rajkosto). These parameters are consistent across
all Tegra variants (APX 2600, T20, T30, T114, T124, T210) — the boot ROM IRAM layout is
the same for the RCM USB stack.

### IRAM Memory Map During RCM

| Address | Size | Purpose |
|---------|------|---------|
| 0x40005000 | 16 KB | USB DMA buffer 0 |
| 0x40009000 | 16 KB | USB DMA buffer 1 |
| 0x40010000 | — | Stack end (grows downward) / RCM payload start |
| 0x4001F000 | 92 B | Intermezzo (relocator stub) |
| 0x40020000 | ~192 KB | Final payload destination |

### Key Constants

| Constant | Value | Notes |
|----------|-------|-------|
| RCM_DECLARED_LENGTH | 0x30298 | 197,272 — triggers oversized memcpy |
| RCM_HEADER_SIZE | 680 bytes | Payload data starts at byte 680 |
| STACK_END | 0x40010000 | Target for stack smash |
| INTERMEZZO_LOCATION | 0x4001F000 | Return address written into stack |
| PAYLOAD_LOAD_BLOCK | 0x40020000 | Intermezzo copies payload here |
| PACKET_SIZE | 0x1000 | USB bulk write chunk size |
| PAYLOAD_MAX | 192 KB | Max payload after RCM header |

### USB Endpoints

| Endpoint | Direction | Purpose |
|----------|-----------|---------|
| 0x01 | Bulk OUT | Send RCM command + payload |
| 0x81 | Bulk IN | Read device ID (16 bytes) + payload responses |

### Exploit Sequence

1. **Read device ID**: 16 bytes from EP 0x81
2. **Build RCM packet**:
   - Bytes 0-3: length = `0x30298` (little-endian)
   - Bytes 4-679: zeros (RCM command padding)
   - Bytes 680+: payload body → maps to IRAM 0x40010000+
3. **Payload body layout** (offsets from byte 680):
   - `[0x0000 - 0xEFFF]`: Return address sled — `0x4001F000` repeated (60 KB)
   - `[0xF000 - 0xF05B]`: Intermezzo binary (92 bytes)
   - `[0xF05C - 0xFFFF]`: Padding
   - `[0x10000 - ...]`: Actual user payload
   - Padded to 192 KB total
4. **Send RCM packet** via bulk EP 0x01 in 0x1000-byte chunks (each write toggles DMA buffer)
5. **Switch to high buffer**: if current DMA buffer is 0, send one more 0x1000-byte write to toggle to buffer 1 (0x40009000)
6. **Smash the stack**: send USB GET_STATUS with `wLength = 0x40010000 - 0x40009000 = 0x7000`
   - libusbk IOCTL: `LIBUSB_IOCTL_GET_STATUS (0x807)`, recipient=endpoint
   - The GET_STATUS triggers memcpy from DMA buffer 1 into the stack
   - Stack return address overwritten with `0x4001F000`
   - Device times out (`ERROR_SEM_TIMEOUT`) — exploit succeeded
7. **Intermezzo runs**: copies payload from 0x4001F020 to 0x40020000, jumps to entry
8. **Payload executes**: bare-metal ARM code with full IRAM/IROM access

### Payload Readback Protocol

After the exploit, the payload can send data back via USB EP 0x81. TegraRcmSmash expects:
- `"READY.\n"` — payload is ready for commands
- Host sends `"RECV"` to request data
- Payload sends data in bulk IN transfers

### APX 2600 Differences

The only difference from standard Tegra RCM is the USB PID:
- Standard RCM (Switch, etc.): `VID 0x0955, PID 0x7321`
- Zune HD APX mode: `VID 0x0955, PID 0x7416`

The USB2D device controller on the APX 2600 is at PA `0xC5004000` (not `0x7D004000`). This
matters for the payload (which programs the USB controller to send data back), but NOT for
the exploit itself (which uses the boot ROM's already-initialized USB stack).

### Intermezzo Binary (92 bytes)

```
44 00 9F E5 01 11 A0 E3 40 20 9F E5 00 20 42 E0
08 00 00 EB 01 01 A0 E3 10 FF 2F E1 00 00 A0 E1
2C 00 9F E5 2C 10 9F E5 02 28 A0 E3 01 00 00 EB
20 00 9F E5 10 FF 2F E1 04 30 90 E4 04 30 81 E4
04 20 52 E2 FB FF FF 1A 1E FF 2F E1 20 F0 01 40
5C F0 01 40 00 00 02 40 00 00 01 40
```
