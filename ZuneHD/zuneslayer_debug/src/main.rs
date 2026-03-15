#![feature(str_from_utf16_endian)]
#![allow(unused_variables)]
#![allow(unreachable_code)]
#![allow(dead_code)]

use crate::zunecom::command_resp::ResType;
use crate::zunecom::command_req::PayloadRdfile;
use crate::zunecom::CommandResp;
use prost::Message;
extern crate core;


use crate::zunecom::command_req::PayloadLsdir;
use crate::zunecom::command_req::CommandType;
use crate::zunecom::CommandReq;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::PathBuf;
use std::time::Duration;
use indicatif::{ProgressBar, ProgressStyle};
use serde::Serialize;
use tracing::{error, info, warn};

#[derive(Debug)]
struct Reg {
    r0: u32,
    r1: u32,
    r2: u32,
    r3: u32,
    pc: u32,
    lr: u32,
    sp: u32,
}
fn getregs(tcp: &mut TcpStream, t: u32) -> Reg {
    let mut c = Vec::new();
    c.push(8u8);
    c.extend_from_slice(t.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 64];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 8);

    let r0 = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    let r1 = u32::from_le_bytes(iubu[5..][..4].try_into().unwrap());
    let r2 = u32::from_le_bytes(iubu[9..][..4].try_into().unwrap());
    let r3 = u32::from_le_bytes(iubu[13..][..4].try_into().unwrap());
    let pc = u32::from_le_bytes(iubu[17..][..4].try_into().unwrap());
    let lr = u32::from_le_bytes(iubu[21..][..4].try_into().unwrap());
    let sp = u32::from_le_bytes(iubu[25..][..4].try_into().unwrap());

    Reg {
        r0,
        r1,
        r2,
        r3,
        pc,
        lr,
        sp
    }
}

fn dbgcont(tcp: &mut TcpStream, p: u32, t: u32) {
    let mut c = Vec::new();
    c.push(7u8);
    c.extend_from_slice(p.to_le_bytes().as_slice());
    c.extend_from_slice(t.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 7);
}
fn dbgwait(tcp: &mut TcpStream) -> Option<(u32, u32, u32)> {
    let mut c = Vec::new();
    c.push(6u8);
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 6);
    let ret = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    let code = u32::from_le_bytes(iubu[5..][..4].try_into().unwrap());
    let proc = u32::from_le_bytes(iubu[9..][..4].try_into().unwrap());
    let thdr = u32::from_le_bytes(iubu[13..][..4].try_into().unwrap());

    if ret == 0 {
        None
    } else {
        Some((code, proc, thdr))
    }
}

fn dbgcon(tcp: &mut TcpStream, addr: u32) -> u32 {
    let mut c = Vec::new();
    c.push(5u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 5);
    let val = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    val
}

fn pwrite32(tcp: &mut TcpStream, hdl: u32, addr: u32, v: u32) {
    let mut c = Vec::new();
    c.push(4u8);
    c.extend_from_slice(hdl.to_le_bytes().as_slice());
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.extend_from_slice(v.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 4);
    let tmp = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    let e = u32::from_le_bytes(iubu[6..][..4].try_into().unwrap());
    let ret = iubu[5];
    if ret == 0 {
        panic!();
        return;
    } else {
        assert_eq!(tmp, 4);
    }
}

fn pread32(tcp: &mut TcpStream, hdl: u32, addr: u32) -> Option<u32> {
    let mut c = Vec::new();
    c.push(3u8);
    c.extend_from_slice(hdl.to_le_bytes().as_slice());
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 3);
    let tmp = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    let val = u32::from_le_bytes(iubu[5..][..4].try_into().unwrap());
    let ret = iubu[9];
    if ret == 0 {
        return None;
    } else {
        assert_eq!(val, 4);
        return Some(tmp);
    }
}

fn openproc(tcp: &mut TcpStream, addr: u32) -> u32 {
    let mut c = Vec::new();
    c.push(2u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 2);
    let val = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    val
}

fn kread_u32(tcp: &mut TcpStream, addr: u32) -> u32 {
    let mut c = Vec::new();
    c.push(1u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 1);
    let val = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    val
}

fn kkill(tcp: &mut TcpStream, addr: u32) {
    let mut c = Vec::new();
    c.push(12u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 32];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 12);
}

fn klistfile(tcp: &mut TcpStream, addr: u32, p: u32) -> String {
    let mut c = Vec::new();
    c.push(13u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.extend_from_slice(p.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut iubu = [0u8; 512];
    tcp.read(&mut iubu).unwrap();
    assert_eq!(iubu[0], 13);
    // println!("{iubu:x?}");

    let mut s = String::new();
    let mut i = &iubu[1..];
    loop {
        let c = u16::from_le_bytes(i[..2].try_into().unwrap());
        if c == 0 {
            break;
        }
        let c = char::from_u32(c as u32).unwrap();
        s.push(c);
        i = &i[2..];
    }
    s
}

fn kreadfile(tcp: &mut TcpStream, addr: u32, p: u32) -> Vec<u8> {
    let mut c = Vec::new();
    c.push(14u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.extend_from_slice(p.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    const SZ: usize = 0x600000;

    let mut iubu = [0u8; SZ + 4];
    let mut o = Vec::new();
    loop {
        let c = tcp.read(&mut iubu).unwrap();
     //   println!("c = {:x}", o.len());
        o.extend_from_slice(&iubu[..c]);
        if o.len() >= iubu.len() {
            break;
        }
    }
    let sz = u32::from_le_bytes(o[..4].try_into().unwrap());
    let o = o[4..][..sz as usize].to_vec();
    if sz as usize == SZ {
        panic!("buf too smol");
    }
    // println!("{iubu:x?}");
    o
}

fn physdump(tcp: &mut TcpStream, addr: u32, offset: u32, sz: u32, filename: &str) {
    println!("[*] Dumping 0x{:08x}+0x{:x} ({}KB) -> {}", addr, offset, sz/1024, filename);

    let mut c = Vec::new();
    c.push(15u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.extend_from_slice(offset.to_le_bytes().as_slice());
    c.extend_from_slice(sz.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut buf = [0u8; 4096];
    let mut o = Vec::new();
    let target = sz as usize - 1;
    loop {
        let n = tcp.read(&mut buf).unwrap();
        o.extend_from_slice(&buf[..n]);
        if o.len() % 0x4000 == 0 || o.len() >= target {
            println!("  {:x}/{:x} ({:.0}%)", o.len(), target, o.len() as f64 / target as f64 * 100.0);
        }
        if o.len() >= target {
            break;
        }
    }
    std::fs::write(filename, &o).unwrap();
    println!("[+] {} written ({} bytes)", filename, o.len());
}

fn dump_via_kread(tcp: &mut TcpStream, vaddr: u32, sz: u32, filename: &str) {
    println!("[*] kread 0x{:08x} ({}B) -> {}", vaddr, sz, filename);
    let mut data = Vec::new();
    for off in (0..sz).step_by(4) {
        let val = kread_u32(tcp, vaddr + off);
        data.extend_from_slice(&val.to_le_bytes());
        if off % 0x100 == 0 && off > 0 {
            print!("  0x{:x}..  \r", off);
        }
    }
    std::fs::write(filename, &data).unwrap();
    println!("[+] {} written ({} bytes)", filename, data.len());
}

// Cmd 20: Kernel DWORD write via kwr gadget
fn kwrite_u32(tcp: &mut TcpStream, addr: u32, val: u32) -> bool {
    let mut c = Vec::new();
    c.push(20u8);
    c.extend_from_slice(addr.to_le_bytes().as_slice());
    c.extend_from_slice(val.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut resp = [0u8; 32];
    tcp.read_exact(&mut resp).unwrap();
    if resp[0] != 20 {
        eprintln!("    [!] kwrite_u32: unexpected response byte 0x{:02x} (expected 20)", resp[0]);
        eprintln!("    [!] cmd 20 may not be supported — is the payload up to date?");
        // Drain any extra bytes the device sent for an unknown cmd
        return false;
    }
    true
}

// Cmd 19: Physical I/O read via VirtualCopy (user-mode MMIO mapping)
fn io_read_vc(tcp: &mut TcpStream, phys_addr: u32, offset: u32, count: u32) -> Result<Vec<u8>, String> {
    let mut c = Vec::new();
    c.push(19u8);
    c.extend_from_slice(phys_addr.to_le_bytes().as_slice());
    c.extend_from_slice(offset.to_le_bytes().as_slice());
    c.extend_from_slice(count.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).map_err(|e| format!("send failed: {}", e))?;

    let mut resp = [0u8; 32];
    tcp.read_exact(&mut resp).map_err(|e| format!("resp read: {}", e))?;
    if resp[0] != 19 { return Err(format!("bad cmd byte: {} (expected 19)", resp[0])); }

    let ok = resp[1];
    let err_code = u32::from_le_bytes(resp[2..6].try_into().unwrap());
    let mapped_va = u32::from_le_bytes(resp[6..10].try_into().unwrap());
    println!("    ok={} err=0x{:x} mapped_va=0x{:08x}", ok, err_code, mapped_va);

    if ok == 1 {
        let mut data = vec![0u8; count as usize];
        tcp.read_exact(&mut data).map_err(|e| format!("data read: {}", e))?;
        Ok(data)
    } else {
        Err(format!("VirtualCopy failed: err=0x{:x}, mapped_va=0x{:08x}", err_code, mapped_va))
    }
}

fn io_dump_vc(tcp: &mut TcpStream, phys_addr: u32, offset: u32, count: u32, filename: &str) -> Option<Vec<u8>> {
    println!("[*] VirtualCopy read PA 0x{:08x}+0x{:x} ({}B) -> {}", phys_addr, offset, count, filename);
    match io_read_vc(tcp, phys_addr, offset, count) {
        Ok(data) => {
            std::fs::write(filename, &data).unwrap();
            for i in (0..std::cmp::min(data.len(), 64)).step_by(4) {
                let v = u32::from_le_bytes(data[i..i+4].try_into().unwrap());
                print!("  +0x{:02x}: 0x{:08x}", i, v);
                if (i/4) % 4 == 3 { println!(); }
            }
            println!();
            println!("[+] {} ({} bytes)", filename, data.len());
            Some(data)
        }
        Err(e) => {
            println!("[-] FAIL: {}", e);
            None
        }
    }
}

// Cmd 17: Uncached I/O read (diagnostic version)
fn io_read(tcp: &mut TcpStream, phys_addr: u32, offset: u32, count: u32) -> Result<Vec<u8>, String> {
    let mut c = Vec::new();
    c.push(17u8);
    c.extend_from_slice(phys_addr.to_le_bytes().as_slice());
    c.extend_from_slice(offset.to_le_bytes().as_slice());
    c.extend_from_slice(count.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).map_err(|e| format!("send failed: {}", e))?;

    // Try to read whatever the device sends back, even partial
    let mut raw = [0u8; 4096];

    // First, try non-blocking peek to see if anything arrives
    // Then fall back to read_exact with timeout
    let mut resp = [0u8; 32];
    match tcp.read_exact(&mut resp) {
        Ok(()) => {}
        Err(e) => {
            // Try a raw read to see if we got partial data
            eprintln!("    [diag] read_exact failed: {}", e);
            match tcp.read(&mut raw) {
                Ok(n) => {
                    eprintln!("    [diag] partial read got {} bytes: {:02x?}", n, &raw[..n]);
                }
                Err(e2) => {
                    eprintln!("    [diag] follow-up read also failed: {}", e2);
                }
            }
            return Err(format!("resp read: {}", e));
        }
    }

    eprintln!("    [diag] resp[0..10]: {:02x?}", &resp[..10]);

    if resp[0] != 17 {
        eprintln!("    [diag] unexpected cmd byte, full resp: {:02x?}", &resp[..]);
        return Err(format!("bad cmd byte: {} (expected 17)", resp[0]));
    }
    let ok = resp[1];
    let mapped = u32::from_le_bytes(resp[2..6].try_into().unwrap());
    let err_code = u32::from_le_bytes(resp[6..10].try_into().unwrap());
    println!("    ok={} mapped_va=0x{:08x} err_code=0x{:08x}", ok, mapped, err_code);
    eprintln!("    [diag] full status: {:02x?}", &resp[..32]);

    if ok == 1 {
        // Read data stream
        let mut data = vec![0u8; count as usize];
        tcp.read_exact(&mut data).map_err(|e| format!("data read: {}", e))?;
        Ok(data)
    } else {
        Err(format!("mapping failed: ok={}, mapped_va=0x{:08x}, err_code=0x{:08x}", ok, mapped, err_code))
    }
}

// Try io_read with retries + connection health check between attempts
fn io_read_retry(tcp: &mut TcpStream, phys_addr: u32, offset: u32, count: u32, retries: u32) -> Result<Vec<u8>, String> {
    for attempt in 0..retries {
        if attempt > 0 {
            eprintln!("    [retry {}/{}]", attempt + 1, retries);
            // Drain any stale data from the socket before retrying
            let old_timeout = tcp.read_timeout().unwrap();
            tcp.set_read_timeout(Some(Duration::from_millis(500))).ok();
            let mut drain = [0u8; 4096];
            while let Ok(n) = tcp.read(&mut drain) {
                if n == 0 { break; }
                eprintln!("    [drain] discarded {} bytes: {:02x?}", n, &drain[..std::cmp::min(n, 32)]);
            }
            tcp.set_read_timeout(old_timeout).ok();

            // Verify the connection is still alive with a kread_u32 probe
            eprintln!("    [probe] testing cmd 1 (kread_u32)...");
            let probe_val = kread_u32(tcp, 0x80bee010);
            eprintln!("    [probe] kread_u32(0x80bee010) = 0x{:08x} — connection alive", probe_val);
        }
        match io_read(tcp, phys_addr, offset, count) {
            Ok(data) => return Ok(data),
            Err(e) => {
                eprintln!("    [attempt {}] failed: {}", attempt + 1, e);
                if attempt + 1 == retries {
                    return Err(e);
                }
            }
        }
    }
    Err("exhausted retries".to_string())
}

// Cmd 18: Uncached I/O write
fn io_write(tcp: &mut TcpStream, phys_addr: u32, offset: u32, val: u32) -> Result<(), String> {
    let mut c = Vec::new();
    c.push(18u8);
    c.extend_from_slice(phys_addr.to_le_bytes().as_slice());
    c.extend_from_slice(offset.to_le_bytes().as_slice());
    c.extend_from_slice(val.to_le_bytes().as_slice());
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    let mut resp = [0u8; 32];
    tcp.read_exact(&mut resp).map_err(|e| format!("resp read: {}", e))?;
    if resp[0] != 18 { return Err(format!("bad cmd byte: {}", resp[0])); }
    if resp[1] == 1 { Ok(()) }
    else {
        let code = u32::from_le_bytes(resp[2..6].try_into().unwrap());
        Err(format!("VirtualCopy failed, error={}", code))
    }
}

fn io_dump(tcp: &mut TcpStream, phys_addr: u32, offset: u32, count: u32, filename: &str) {
    println!("[*] IO read 0x{:08x}+0x{:x} ({}B) -> {}", phys_addr, offset, count, filename);
    match io_read(tcp, phys_addr, offset, count) {
        Ok(data) => {
            std::fs::write(filename, &data).unwrap();
            // Print first few u32s
            for i in (0..std::cmp::min(data.len(), 32)).step_by(4) {
                let v = u32::from_le_bytes(data[i..i+4].try_into().unwrap());
                print!("  +0x{:02x}: 0x{:08x}", i, v);
                if (i/4) % 4 == 3 { println!(); }
            }
            println!();
            println!("[+] {} ({} bytes)", filename, data.len());
        }
        Err(e) => println!("[-] FAIL: {}", e),
    }
}

fn scan_kernel_pagetable(tcp: &mut TcpStream) {
    // On ARMv6 (Tegra APX 2600 = ARM1176), the Translation Table Base Register (TTBR)
    // points to a 16KB L1 page table with 4096 entries (one per 1MB section).
    //
    // On WinCE 6.0, the kernel's L1 page table is at a known location.
    // KData is at 0x80bee000. The page directory is typically at a fixed VA.
    // On CE6 ARM, the kernel page directory is often at 0xFFFD0000 (mapped by hardware)
    // but we can't read that directly. Instead, it's often stored in the KData area.
    //
    // Alternative: read CP15 TTBR via the existing kernel structures.
    // On CE6, KData+0x1B4 often contains the first-level page table physical address.
    // Or we can look at the OEMAddressTable processing code to find where it stores the PT.
    //
    // Simpler: just try to read L1 page table entries for the VAs we care about.
    // On ARM, L1 table entry for VA X is at: TTBR_base + (X >> 20) * 4
    //
    // The kernel maps its own page table at a known VA. On CE6:
    // The "FirstPT" (first level page table) is at KPage+0x400 area, but
    // it's easier to just search for it.
    //
    // Let's try to find TTBR by reading KData area.

    println!("=== Scanning for kernel page table (TTBR) ===");

    // KData is at 0x80bee000. Read the KData structure to find page table pointer.
    // On WinCE 6, _KDATA has many fields. The page table info is typically stored
    // at known offsets. Let's dump a chunk of KData and look for pointers to
    // page-table-looking addresses.

    // First, let's read the value that the OAL stores.
    // On CE6 ARM, the kernel page directory physical address is often at:
    // pTOC->ulRAMFree or stored during OEMAddressTable processing.
    // The page directory VA is typically 0xFFFD0000.
    //
    // But actually - the simplest approach: if we know the page directory is at
    // some kernel VA, we can read it with kread_u32. Let's try 0xFFFD0000.
    // On CE6 ARM, the kernel maps its own page table at 0xFFFD0000-0xFFFD3FFF.

    println!("[*] Trying kernel page directory at VA 0xFFFD0000...");
    let test = kread_u32(tcp, 0xFFFD0000);
    println!("    PD[0x000] (VA 0x00000000) = 0x{:08x}", test);

    // If this worked, PD entry for VA 0x9F600000:
    // index = 0x9F600000 >> 20 = 0x9F6
    // PD addr = 0xFFFD0000 + 0x9F6 * 4 = 0xFFFD27D8
    let idx_9f6 = 0x9F6u32;
    let pd_entry = kread_u32(tcp, 0xFFFD0000 + idx_9f6 * 4);
    println!("    PD[0x{:03x}] (VA 0x9F600000) = 0x{:08x}", idx_9f6, pd_entry);

    // Check entries for all our target VAs
    let targets = vec![
        (0x800u32, "0x80000000 (RAM)"),
        (0x80Bu32, "0x80B00000 (near KData)"),
        (0x9F4u32, "0x9F400000 (IRAM)"),
        (0x9F5u32, "0x9F500000 (APB)"),
        (0x9F6u32, "0x9F600000 (AHB/CLK/SecBoot)"),
        (0x9F7u32, "0x9F700000 (Fuse/PMC)"),
        (0x9FFu32, "0x9FF00000 (IROM)"),
        (0xBF6u32, "0xBF600000 (uncached AHB)"),
        (0xBF7u32, "0xBF700000 (uncached Fuse)"),
        (0xBFFu32, "0xBFF00000 (uncached IROM)"),
    ];

    println!("\n  L1 Page Table Entries:");
    for (idx, desc) in &targets {
        let entry = kread_u32(tcp, 0xFFFD0000 + idx * 4);
        let entry_type = entry & 0x3;
        let type_str = match entry_type {
            0 => "FAULT (unmapped!)",
            1 => "coarse page table",
            2 => "section (1MB)",
            3 => "reserved",
            _ => "?",
        };
        let pa = entry & 0xFFF00000;
        println!("    PD[0x{:03x}] {} = 0x{:08x} [{}] PA=0x{:08x}", idx, desc, entry, type_str, pa);
    }

    println!("\n[DONE] Use the above to determine which VAs are actually mapped.");
}

fn dump_via_virtualcopy(tcp: &mut TcpStream) {
    std::fs::create_dir_all("dumps").unwrap();

    // === Phase 1: Validate cmd 19 ===
    println!("=== Phase 1: Validate cmd 19 (VirtualCopy) ===");
    println!("[*] Probing CLK_RST_SOURCE (PA 0x60006000)...");
    match io_read_vc(tcp, 0x60006000, 0x0, 4) {
        Ok(data) => {
            let v = u32::from_le_bytes(data[..4].try_into().unwrap());
            println!("[+] CLK_RST_SOURCE = 0x{:08x} — cmd 19 works!", v);
        }
        Err(e) => {
            println!("[-] cmd 19 probe failed: {}", e);
            println!("    VirtualCopy may not work for I/O addresses on this firmware");
            return;
        }
    }

    // === Phase 2: Register dumps ===
    println!("\n=== Phase 2: Register Dumps ===");
    let ahb_data  = io_dump_vc(tcp, 0x6000C000, 0x0, 0x100, "dumps/ahb_arb.bin");
    let sb_data   = io_dump_vc(tcp, 0x6000C200, 0x0, 0x100, "dumps/secboot.bin");
    let bsev_data = io_dump_vc(tcp, 0x60011000, 0x0, 0x100, "dumps/bsev.bin");
    let _clk_data = io_dump_vc(tcp, 0x60006000, 0x0, 0x400, "dumps/clk_rst.bin");
    let fuse_data = io_dump_vc(tcp, 0x7000F800, 0x0, 0x400, "dumps/fuse.bin");

    // === Phase 3: Analysis ===
    println!("\n=== Phase 3: Register Analysis ===");
    if let Some(ref d) = ahb_data { analyze_ahb(d); }
    if let Some(ref d) = sb_data { analyze_secboot(d); }
    if let Some(ref d) = fuse_data { analyze_fuse(d); }
    if let Some(ref d) = bsev_data { analyze_bsev(d); }

    // === Phase 4: IROM ===
    println!("\n=== Phase 4: IROM Probe (PA 0xFFF00000) ===");
    match io_read_vc(tcp, 0xFFF00000, 0x0, 16) {
        Ok(data) => {
            for i in (0..data.len()).step_by(4) {
                let v = u32::from_le_bytes(data[i..i+4].try_into().unwrap());
                println!("    IROM+0x{:02x} = 0x{:08x}", i, v);
            }
            let first = u32::from_le_bytes(data[..4].try_into().unwrap());
            if first == 0 || first == 0xFFFFFFFF {
                println!("    [-] IROM appears blank/protected");
            } else {
                println!("    [+] IROM readable! Dumping full 64KB...");
                // Dump in 4KB chunks (VirtualCopy page size)
                let mut all_data = Vec::new();
                let total = 0x10000u32;
                for off in (0..total).step_by(4096) {
                    let remaining = std::cmp::min(4096, total - off);
                    match io_read_vc(tcp, 0xFFF00000, off, remaining) {
                        Ok(chunk) => {
                            all_data.extend_from_slice(&chunk);
                            println!("    0x{:x}/0x{:x}", off + remaining, total);
                        }
                        Err(e) => {
                            println!("    [-] FAIL at offset 0x{:x}: {}", off, e);
                            break;
                        }
                    }
                }
                if !all_data.is_empty() {
                    std::fs::write("dumps/irom.bin", &all_data).unwrap();
                    println!("[+] dumps/irom.bin ({} bytes)", all_data.len());
                }
            }
        }
        Err(e) => {
            println!("    [-] IROM probe failed: {}", e);
        }
    }

    println!("\n[DONE]");
}

fn bsev_dma_irom_dump(tcp: &mut TcpStream) {
    std::fs::create_dir_all("dumps").unwrap();

    // Uncached kernel VAs (confirmed via page table):
    //   PA 0x60000000 -> VA 0xBF600000 (AHB/CLK_RST/SecBoot)
    //   PA 0x40000000 -> VA 0xBF400000 (IRAM) -- need to verify this is mapped
    //   PA 0xFFF00000 -> VA 0xBFF00000 (IROM)

    // BSEV (Video Bitstream Engine) is at PA 0x6001B000 -> VA 0xBF61B000
    // BSEA (Audio Bitstream Engine) is at PA 0x60011000 -> VA 0xBF611000
    // Both are AES DMA engines that operate on the AHB bus, bypassing CPU PIROM_DISABLE.

    let clk_rst_va: u32 = 0xBF606000;   // PA 0x60006000
    let bsev_va: u32    = 0xBF61B000;    // PA 0x6001B000
    let bsea_va: u32    = 0xBF611000;    // PA 0x60011000

    // IRAM is at PA 0x40000000. Check if it's mapped.
    // From OEMAddressTable: PA 0x40000000 -> VA 0x9F400000 (cached)
    // Check page table for uncached mirror at 0xBF400000
    println!("=== Phase 0: Check page table for IRAM mapping ===");
    let iram_pd = kread_u32(tcp, 0xFFFD0000 + 0xBF4 * 4);
    println!("    PD[0xBF4] (VA 0xBF400000, IRAM) = 0x{:08x} [type={}]",
        iram_pd, if iram_pd & 3 == 2 { "section" } else if iram_pd & 3 == 0 { "FAULT" } else { "other" });

    // Also check cached IRAM
    let iram_cached_pd = kread_u32(tcp, 0xFFFD0000 + 0x9F4 * 4);
    println!("    PD[0x9F4] (VA 0x9F400000, IRAM cached) = 0x{:08x} [type={}]",
        iram_cached_pd, if iram_cached_pd & 3 == 2 { "section" } else if iram_cached_pd & 3 == 0 { "FAULT" } else { "other" });

    // We can also use RAM as DMA destination. RAM is at VA 0x80000000+ (always mapped).
    // Let's use a high RAM address that's unlikely to be in use.
    // Or we can use IRAM if it's mapped.

    // === Phase 1: Enable VDE + BSEV clocks ===
    println!("\n=== Phase 1: Enable VDE + BSEV clocks ===");

    // CLK_OUT_ENB_H is at CLK_RST + 0x014 (clocks 32-63)
    // BSEV = clock 63 -> bit 31 of CLK_OUT_ENB_H
    // VDE  = clock 61 -> bit 29 of CLK_OUT_ENB_H
    let clk_enb_h_va = clk_rst_va + 0x014;
    let rst_dev_h_va = clk_rst_va + 0x008;

    let clk_enb_h = kread_u32(tcp, clk_enb_h_va);
    println!("    CLK_OUT_ENB_H = 0x{:08x}", clk_enb_h);
    println!("    VDE clock (bit 29) = {}", (clk_enb_h >> 29) & 1);
    println!("    BSEV clock (bit 31) = {}", (clk_enb_h >> 31) & 1);

    let rst_dev_h = kread_u32(tcp, rst_dev_h_va);
    println!("    RST_DEVICES_H = 0x{:08x}", rst_dev_h);
    println!("    VDE reset (bit 29) = {}", (rst_dev_h >> 29) & 1);
    println!("    BSEV reset (bit 31) = {}", (rst_dev_h >> 31) & 1);

    // Enable VDE + BSEV clocks (set bits 29 and 31)
    let new_clk = clk_enb_h | (1 << 29) | (1 << 31);
    println!("    [*] Writing CLK_OUT_ENB_H = 0x{:08x}", new_clk);
    if !kwrite_u32(tcp, clk_enb_h_va, new_clk) {
        println!("    [-] kwrite failed — cmd 20 not available");
        println!("    Cannot proceed without kernel write capability");
        return;
    }

    // Deassert reset for VDE + BSEV (clear bits 29 and 31 in RST_DEVICES_H)
    let new_rst = rst_dev_h & !((1 << 29) | (1 << 31));
    println!("    [*] Writing RST_DEVICES_H = 0x{:08x}", new_rst);
    kwrite_u32(tcp, rst_dev_h_va, new_rst);

    // Small delay for clocks to stabilize
    std::thread::sleep(std::time::Duration::from_millis(100));

    // Verify
    let clk_verify = kread_u32(tcp, clk_enb_h_va);
    let rst_verify = kread_u32(tcp, rst_dev_h_va);
    println!("    CLK_OUT_ENB_H verify = 0x{:08x} (VDE={}, BSEV={})",
        clk_verify, (clk_verify >> 29) & 1, (clk_verify >> 31) & 1);
    println!("    RST_DEVICES_H verify = 0x{:08x} (VDE={}, BSEV={})",
        rst_verify, (rst_verify >> 29) & 1, (rst_verify >> 31) & 1);

    // === Phase 2: Check BSEV is alive ===
    println!("\n=== Phase 2: Probe BSEV at VA 0x{:08x} ===", bsev_va);
    let bsev_probe = kread_u32(tcp, bsev_va);
    println!("    BSEV+0x000 = 0x{:08x}", bsev_probe);
    if bsev_probe == 0xD0D0CACA || bsev_probe == 0xCACAD0D0 {
        println!("    [-] BSEV still returning bus error after clock enable");
        println!("    Trying BSEA at VA 0x{:08x} as fallback...", bsea_va);
        let bsea_probe = kread_u32(tcp, bsea_va);
        println!("    BSEA+0x000 = 0x{:08x}", bsea_probe);
        if bsea_probe == 0xD0D0CACA || bsea_probe == 0xCACAD0D0 {
            println!("    [-] BSEA also dead. Clock enable may not have worked.");
            return;
        }
    }

    // Dump first 0x20 of BSEV registers to understand state
    println!("    BSEV register dump:");
    for off in (0..0x20u32).step_by(4) {
        let v = kread_u32(tcp, bsev_va + off);
        println!("      BSEV+0x{:03x} = 0x{:08x}", off, v);
    }

    // === Phase 3: Program BSEV DMA to read IROM ===
    println!("\n=== Phase 3: BSEV DMA — read IROM 0xFFF00000 -> IRAM 0x40008000 ===");

    // BSEV AES engine register offsets (from Tegra TRM / U-Boot tegra-aes driver):
    //   0x000: CMDQUE_CONTROL
    //   0x004: INTR_STATUS
    //   0x008: BSE_CONFIG
    //   0x00C: SECURE_SECURITY (security config)
    //   0x010: SECURE_HASH_RESULT (4 words)
    //   0x040: SECURE_SEC_SEL (0-3 for key slot)
    //   0x044: SECURE_CONFIG
    //   0x048: SECURE_CONFIG_EXT
    //   0x04C: SECURE_SECURITY (another)
    //   0x100: SECURE_DEST_ADDR — DMA destination address
    //   0x108: SECURE_INPUT_SELECT — input config + source address

    // For a simple DMA copy we want to use the AES engine in a way that
    // just moves data. We'll try to set up a passthrough/identity operation.

    // The BSEV engine in Tegra20 works as follows:
    // 1. Write commands to the CMDQUE (command queue) via ICMDQUE_WR (0x1C)
    // 2. Commands include: setup DMA, configure AES, start engine, etc.
    // 3. DMA addresses are PHYSICAL addresses (AHB bus addresses)

    // Command opcodes for BSEV:
    // 0x00: ABORT
    // 0x01: NOP
    // 0x02: SETTABLE — set key/IV table (slot select + data)
    // 0x03: BLKSTARTENGINE — start AES on a block
    // 0x04: DMASETUP — configure DMA source
    // 0x05: DMACOMPLETE — finalize DMA
    // 0x06: DMAPAUSE
    // 0x07: MEMDMAVD — memory-to-memory DMA (VDE specific?)

    // Actually, looking at the U-Boot tegra-aes code more carefully:
    // The command format is a 32-bit word where bits [31:26] are the opcode.
    // MEMDMAVD (opcode 0x06) does a straight memory DMA without AES.

    // MEMDMAVD command word:
    //   [31:26] = 0x06 (MEMDMAVD opcode)
    //   [25]    = direction (0=read from memory, 1=write to memory)
    //   [15:0]  = count in 16-byte blocks (0 = 1 block)

    // Let's try 4KB at a time (256 blocks of 16 bytes)
    let block_count = 256u32; // 256 * 16 = 4096 bytes
    let irom_phys: u32 = 0xFFF00000;
    let iram_dest: u32 = 0x40008000; // BSEV IRAM buffer

    // Step 1: Set destination address
    println!("[*] Setting SECURE_DEST_ADDR = 0x{:08x}", iram_dest);
    kwrite_u32(tcp, bsev_va + 0x100, iram_dest);

    // Step 2: Set source address via SECURE_INPUT_SELECT
    // SECURE_INPUT_SELECT format:
    //   [31:16] = source address bits [31:16]
    //   ... complex, let's try writing source addr to the right register
    // Actually in tegra-aes, the DMA setup goes through command queue writes.

    // Let's try the ICMDQUE_WR approach:
    // Write DMASETUP command to set source address
    let dma_setup_cmd = (0x04u32 << 26) | (irom_phys >> 2); // DMASETUP + addr >> 2
    println!("[*] Writing DMASETUP cmd = 0x{:08x}", dma_setup_cmd);
    kwrite_u32(tcp, bsev_va + 0x01C, dma_setup_cmd); // ICMDQUE_WR

    // Write BLKSTARTENGINE command
    let blk_start_cmd = (0x03u32 << 26) | ((block_count - 1) & 0xFFFF);
    println!("[*] Writing BLKSTARTENGINE cmd = 0x{:08x}", blk_start_cmd);
    kwrite_u32(tcp, bsev_va + 0x01C, blk_start_cmd);

    // Write DMACOMPLETE command
    let dma_complete_cmd = 0x05u32 << 26;
    println!("[*] Writing DMACOMPLETE cmd = 0x{:08x}", dma_complete_cmd);
    kwrite_u32(tcp, bsev_va + 0x01C, dma_complete_cmd);

    // Wait for completion
    std::thread::sleep(std::time::Duration::from_millis(500));

    // Check status
    let status = kread_u32(tcp, bsev_va + 0x004);
    println!("    BSEV INTR_STATUS = 0x{:08x}", status);

    // === Phase 4: Read back from IRAM ===
    println!("\n=== Phase 4: Check IRAM for IROM data ===");
    // IRAM at VA 0xBF400000 (if mapped) or we need to check
    let iram_va = if iram_pd & 3 == 2 {
        0xBF400000u32 + 0x8000 // offset to 0x40008000
    } else if iram_cached_pd & 3 == 2 {
        0x9F400000u32 + 0x8000
    } else {
        println!("    [-] IRAM not mapped in page table — cannot read DMA result");
        // Try reading IRAM via the 0x80000000 RAM mapping? No, IRAM is separate.
        // We need the IRAM mapping. Let's check more PD entries.
        println!("    Checking if IRAM is at any other VA...");
        // On the Zune, IRAM might already be accessible at another VA
        // Actually, we already have IRAM dumps from earlier! That means IRAM was readable
        // via cmd 17 before. Let's try using kread_u32 at the known IRAM VA.
        return;
    };

    println!("    Reading IRAM at VA 0x{:08x}...", iram_va);
    for off in [0x0u32, 0x4, 0x8, 0xC, 0x10, 0x14, 0x18, 0x1C] {
        let v = kread_u32(tcp, iram_va + off);
        println!("    IRAM+0x{:04x} = 0x{:08x}", 0x8000 + off, v);
    }

    println!("\n[DONE]");
}

fn dump_registers_and_irom(tcp: &mut TcpStream) {
    std::fs::create_dir_all("dumps").unwrap();

    // Page table scan confirmed these uncached VAs are section-mapped:
    //   0xBF600000 -> PA 0x60000000 (AHB/CLK/SecBoot) — L1 entry 0x60000412
    //   0xBF700000 -> PA 0x70000000 (Fuse/PMC)        — L1 entry 0x70000412
    //   0xBFF00000 -> PA 0xFFF00000 (IROM)            — L1 entry 0xfff00402

    // === Phase 1: Quick validate ===
    println!("=== Phase 1: Validate uncached VA access ===");
    let val = kread_u32(tcp, 0xBF606000);
    println!("    CLK_RST_RST_SOURCE (VA 0xBF606000) = 0x{:08x}", val);

    // === Phase 2: Register dumps ===
    println!("\n=== Phase 2: Register Dumps ===");
    dump_via_kread(tcp, 0xBF60C000, 0x100, "dumps/ahb_arb.bin");    // PA 0x6000C000
    dump_via_kread(tcp, 0xBF60C200, 0x100, "dumps/secboot.bin");     // PA 0x6000C200
    dump_via_kread(tcp, 0xBF611000, 0x100, "dumps/bsev.bin");        // PA 0x60011000
    dump_via_kread(tcp, 0xBF606000, 0x400, "dumps/clk_rst.bin");     // PA 0x60006000
    // Fuse controller crashes on access — clock may need enabling first. Skip for now.
    // dump_via_kread(tcp, 0xBF70F800, 0x30, "dumps/fuse.bin");

    // === Phase 3: Analysis ===
    println!("\n=== Phase 3: Register Analysis ===");
    if let Ok(d) = std::fs::read("dumps/ahb_arb.bin") { analyze_ahb(&d); }
    if let Ok(d) = std::fs::read("dumps/secboot.bin") { analyze_secboot(&d); }
    if let Ok(d) = std::fs::read("dumps/fuse.bin") { analyze_fuse(&d); }
    if let Ok(d) = std::fs::read("dumps/bsev.bin") { analyze_bsev(&d); }

    // === Phase 4: Attempt to clear PIROM_DISABLE and dump IROM ===
    println!("\n=== Phase 4: IROM Unlock Attempt ===");

    // Read current SB_CSR_0
    let sb_csr = kread_u32(tcp, 0xBF60C200);
    println!("    SB_CSR_0 = 0x{:08x}", sb_csr);
    println!("    PIROM_DISABLE={}, NS_LOCK={}", (sb_csr >> 4) & 1, sb_csr & 1);

    if (sb_csr >> 4) & 1 == 1 {
        if sb_csr & 1 == 1 {
            println!("    [-] NS_LOCK=1 — write-once lock active, cannot clear PIROM_DISABLE");
        } else {
            println!("    [*] NS_LOCK=0 — attempting to clear PIROM_DISABLE (bit 4)...");
            let new_csr = sb_csr & !0x10; // clear bit 4
            println!("    [*] Writing SB_CSR_0 = 0x{:08x} (VA 0xBF60C200)", new_csr);
            kwrite_u32(tcp, 0xBF60C200, new_csr);

            // Verify
            let verify = kread_u32(tcp, 0xBF60C200);
            println!("    [*] SB_CSR_0 readback = 0x{:08x}", verify);
            if (verify >> 4) & 1 == 0 {
                println!("    [+] PIROM_DISABLE cleared successfully!");
            } else {
                println!("    [-] PIROM_DISABLE still set — register may be write-protected by fuses");
            }
        }
    } else {
        println!("    [+] PIROM_DISABLE already clear");
    }

    // === Phase 5: IROM dump ===
    println!("\n=== Phase 5: IROM Dump (VA 0xBFF00000, PA 0xFFF00000, 64KB) ===");
    let irom_probe = kread_u32(tcp, 0xBFF00000);
    println!("    IROM+0x00 = 0x{:08x}", irom_probe);

    // Probe a few more offsets
    for off in [0x4u32, 0x8, 0xC, 0x10, 0x100] {
        let v = kread_u32(tcp, 0xBFF00000 + off);
        println!("    IROM+0x{:04x} = 0x{:08x}", off, v);
    }

    // Check if we're getting real data
    let first = irom_probe;
    if first == 0x00000000 || first == 0xFFFFFFFF || first == 0xd0d0caca {
        println!("    [-] IROM still appears protected or blank");
        println!("    PIROM_DISABLE may be fuse-enforced despite NS_LOCK=0");
    } else {
        println!("    [+] IROM data looks real! Dumping full 64KB...");
        dump_via_kread(tcp, 0xBFF00000, 0x10000, "dumps/irom.bin");
        println!("[+] IROM dump complete!");
    }

    println!("\n[DONE]");
}

fn find_oem_address_table(tcp: &mut TcpStream) {
    // OEMAddressTable is an array of (VA: u32, PA: u32, sizeMB: u32) entries.
    // We scan kernel memory looking for entries where:
    //   - VA is in 0x80000000..0xC0000000 (kernel cached) or 0xA0000000..0xC0000000 (uncached)
    //   - PA matches known Tegra2 ranges (0x00000000=RAM, 0x40000000=IRAM, 0x50000000=APB, 0x60000000=AHB, 0x70000000=misc, 0xFFF00000=IROM)
    //   - sizeMB is small (1..256)
    //   - Table ends with (0,0,0)
    //
    // Common kernel data locations to scan: around KData (0x80bee000 area) or
    // early in the kernel image (0x80001000..0x80100000).

    // Strategy: scan known kernel regions for the table signature
    let scan_ranges: Vec<(u32, u32)> = vec![
        (0x80001000, 0x80020000),  // early kernel image
        (0x80020000, 0x80060000),  // kernel code/data
        (0x80060000, 0x800A0000),  // more kernel data
        (0x800A0000, 0x80100000),  // extended kernel
    ];

    for (start, end) in &scan_ranges {
        println!("[*] Scanning 0x{:08x}..0x{:08x} for OEMAddressTable", start, end);
        for addr in (*start..*end).step_by(4) {
            // Read a candidate entry: (VA, PA, sizeMB)
            let va = kread_u32(tcp, addr);

            // Quick filter: VA must be in kernel range
            if va < 0x80000000 || va >= 0xC0000000 {
                continue;
            }

            let pa = kread_u32(tcp, addr + 4);
            let sz = kread_u32(tcp, addr + 8);

            // PA should be page-aligned
            if pa & 0xFFFFF != 0 && pa != 0 {
                continue;
            }

            // Size should be reasonable (1-256 MB)
            if sz == 0 || sz > 256 {
                continue;
            }

            // Check if PA is a known Tegra2 physical range
            let pa_top = pa >> 28;
            let is_tegra_pa = pa_top == 0x0 || pa_top == 0x4 || pa_top == 0x5 ||
                              pa_top == 0x6 || pa_top == 0x7 || pa_top == 0xF;
            if !is_tegra_pa {
                continue;
            }

            // Looks promising — read more entries to validate it's a table
            println!("  [?] candidate @ 0x{:08x}: VA=0x{:08x} PA=0x{:08x} size={}MB", addr, va, pa, sz);

            let mut valid_entries = 0;
            let mut entries = Vec::new();
            for i in 0..32 {
                let e_va = kread_u32(tcp, addr + i * 12);
                let e_pa = kread_u32(tcp, addr + i * 12 + 4);
                let e_sz = kread_u32(tcp, addr + i * 12 + 8);

                if e_va == 0 && e_pa == 0 && e_sz == 0 {
                    // Terminator found!
                    if valid_entries >= 3 {
                        println!("\n  [+] FOUND OEMAddressTable @ 0x{:08x} ({} entries)", addr, valid_entries);
                        for (v, p, s) in &entries {
                            println!("      VA=0x{:08x} PA=0x{:08x} size={}MB", v, p, s);
                            // Identify what each mapping covers
                            let desc = match *p >> 24 {
                                0x00u32 => "RAM",
                                0x40 => "IRAM",
                                0x50 => "APB DMA / GPU",
                                0x58 => "APB / GPU",
                                0x60 => "AHB / CLK_RST / Secure Boot",
                                0x68 => "host1x / display",
                                0x70 => "Misc / Fuse / PMC / I2C / UART",
                                0x78 => "EMC / MC",
                                0xF0..=0xFF => "IROM / Boot ROM",
                                _ => "unknown",
                            };
                            println!("        -> {}", desc);
                        }

                        // Now use these mappings to find register VAs
                        println!("\n  === Computed Register Virtual Addresses ===");
                        for (v, p, s) in &entries {
                            let p_end = p + (*s as u32) * 0x100000;
                            // AHB_ARB at PA 0x6000C000
                            if 0x6000C000 >= *p && 0x6000C000 < p_end {
                                let va = v + (0x6000C000 - p);
                                println!("    AHB_ARB (PA 0x6000C000) -> VA 0x{:08x}", va);
                            }
                            // Secure Boot at PA 0x6000C200
                            if 0x6000C200 >= *p && 0x6000C200 < p_end {
                                let va = v + (0x6000C200 - p);
                                println!("    SecBoot (PA 0x6000C200) -> VA 0x{:08x}", va);
                            }
                            // BSEV at PA 0x60011000
                            if 0x60011000 >= *p && 0x60011000 < p_end {
                                let va = v + (0x60011000 - p);
                                println!("    BSEV    (PA 0x60011000) -> VA 0x{:08x}", va);
                            }
                            // CLK_RST at PA 0x60006000
                            if 0x60006000 >= *p && 0x60006000 < p_end {
                                let va = v + (0x60006000 - p);
                                println!("    CLK_RST (PA 0x60006000) -> VA 0x{:08x}", va);
                            }
                            // Fuse at PA 0x7000F800
                            if 0x7000F800 >= *p && 0x7000F800 < p_end {
                                let va = v + (0x7000F800 - p);
                                println!("    FUSE    (PA 0x7000F800) -> VA 0x{:08x}", va);
                            }
                            // IROM at PA 0xFFF00000
                            if 0xFFF00000u32 >= *p && 0xFFF00000u32 < p_end {
                                let va = v + (0xFFF00000u32 - p);
                                println!("    IROM    (PA 0xFFF00000) -> VA 0x{:08x}", va);
                            }
                        }

                        // Dump registers via kread using discovered VAs
                        println!("\n  === Dumping registers via kread_u32 ===");
                        std::fs::create_dir_all("dumps").unwrap();
                        for (v, p, s) in &entries {
                            let p_end = p + (*s as u32) * 0x100000;
                            let targets: Vec<(u32, u32, &str)> = vec![
                                (0x6000C000, 0x100, "dumps/ahb_arb.bin"),
                                (0x6000C200, 0x100, "dumps/secboot.bin"),
                                (0x60011000, 0x100, "dumps/bsev.bin"),
                                (0x60006000, 0x400, "dumps/clk_rst.bin"),
                                (0x7000F800, 0x400, "dumps/fuse.bin"),
                            ];
                            for (pa_target, size, filename) in &targets {
                                if *pa_target >= *p && *pa_target < p_end {
                                    let target_va = v + (pa_target - p);
                                    dump_via_kread(tcp, target_va, *size, filename);
                                }
                            }
                        }

                        // Analyze dumped registers
                        println!("\n  === Register Analysis ===");
                        if let Ok(d) = std::fs::read("dumps/ahb_arb.bin") { analyze_ahb(&d); }
                        if let Ok(d) = std::fs::read("dumps/secboot.bin") { analyze_secboot(&d); }
                        if let Ok(d) = std::fs::read("dumps/fuse.bin") { analyze_fuse(&d); }
                        if let Ok(d) = std::fs::read("dumps/bsev.bin") { analyze_bsev(&d); }

                        // Try IROM
                        for (v, p, s) in &entries {
                            let p_end = p + (*s as u32) * 0x100000;
                            if 0xFFF00000u32 >= *p && 0xFFF00000u32 < p_end {
                                let irom_va = v + (0xFFF00000u32 - p);
                                println!("\n  === IROM Probe (VA 0x{:08x}) ===", irom_va);
                                let probe = kread_u32(tcp, irom_va);
                                println!("    IROM+0x00 = 0x{:08x}", probe);
                                if probe != 0 && probe != 0xFFFFFFFF && probe != 0xd0d0caca {
                                    println!("    Looks like real data! Dumping full 64KB...");
                                    dump_via_kread(tcp, irom_va, 0x10000, "dumps/irom.bin");
                                } else {
                                    println!("    IROM appears protected or unmapped at this VA");
                                }
                            }
                        }

                        return;
                    }
                    break;
                }

                if e_va >= 0x80000000 && e_va < 0xC0000000 && e_sz > 0 && e_sz <= 256 {
                    valid_entries += 1;
                    entries.push((e_va, e_pa, e_sz));
                } else {
                    break;  // not a valid table
                }
            }
        }
    }

    println!("[-] OEMAddressTable not found in scanned ranges");
    println!("    Try scanning wider range or check kernel image for table pointer");
}

fn io_dump_retry(tcp: &mut TcpStream, phys_addr: u32, offset: u32, count: u32, filename: &str) -> Option<Vec<u8>> {
    println!("[*] IO read 0x{:08x}+0x{:x} ({}B) -> {}", phys_addr, offset, count, filename);
    match io_read_retry(tcp, phys_addr, offset, count, 3) {
        Ok(data) => {
            std::fs::write(filename, &data).unwrap();
            for i in (0..std::cmp::min(data.len(), 64)).step_by(4) {
                let v = u32::from_le_bytes(data[i..i+4].try_into().unwrap());
                print!("  +0x{:02x}: 0x{:08x}", i, v);
                if (i/4) % 4 == 3 { println!(); }
            }
            println!();
            println!("[+] {} ({} bytes)", filename, data.len());
            Some(data)
        }
        Err(e) => {
            println!("[-] FAIL: {}", e);
            None
        }
    }
}

fn print_reg(data: &[u8], base_name: &str, offset: usize, name: &str) {
    if offset + 4 <= data.len() {
        let v = u32::from_le_bytes(data[offset..offset+4].try_into().unwrap());
        println!("    {}+0x{:03x} ({}) = 0x{:08x} (0b{:032b})", base_name, offset, name, v, v);
    }
}

fn analyze_ahb(data: &[u8]) {
    println!("\n  --- AHB Arbitration Analysis ---");
    // AHB_ARBITRATION_AHB_MEM_WRQUE_MST_ID_0 = +0x00
    print_reg(data, "AHB_ARB", 0x00, "AHB_MEM_WRQUE_MST_ID");
    // AHB_ARBITRATION_XBAR_CTRL_0 = +0x0C (in our dump that's relative)
    // The key register: AHB_ARBITRATION_USR_PROTECT_0
    // We dumped from 0x6000C000, the USR_PROTECT is at 0x6000C07C offset from AHB base
    // Relative: 0x7C
    if data.len() >= 0x80 {
        print_reg(data, "AHB_ARB", 0x7C, "USR_PROTECT");
        let v = u32::from_le_bytes(data[0x7C..0x80].try_into().unwrap());
        if v & 1 != 0 {
            println!("    !! USR_PROTECT bit 0 SET — AHB may be blocking IROM reads");
        } else {
            println!("    USR_PROTECT bit 0 clear — AHB not blocking");
        }
    }
}

fn analyze_secboot(data: &[u8]) {
    println!("\n  --- Secure Boot Analysis ---");
    // SB_CSR_0 is at offset 0x00 within the secure boot block (0x6000C200)
    print_reg(data, "SB", 0x00, "SB_CSR_0");
    if data.len() >= 4 {
        let csr = u32::from_le_bytes(data[0..4].try_into().unwrap());
        let pirom_disable = (csr >> 4) & 1;
        let secure_boot_flag = (csr >> 1) & 1;
        let ns_lock = csr & 1;
        println!("    PIROM_DISABLE (bit 4) = {} {}", pirom_disable,
            if pirom_disable == 1 { "!! IROM access DISABLED by secure boot" } else { "(IROM accessible)" });
        println!("    SECURE_BOOT_FLAG (bit 1) = {}", secure_boot_flag);
        println!("    NS_LOCK (bit 0) = {} {}", ns_lock,
            if ns_lock == 1 { "!! Write-once lock ACTIVE — cannot clear via software" } else { "(not locked)" });
    }
    // SB_PIROM_START_0 = +0x04
    print_reg(data, "SB", 0x04, "SB_PIROM_START");
    // SB_PFCFG_0 = +0x08
    print_reg(data, "SB", 0x08, "SB_PFCFG");
    // SB_SECURE_SPARE_0..3
    print_reg(data, "SB", 0x0C, "SB_SECURE_SPARE_0");
    print_reg(data, "SB", 0x10, "SB_SECURE_SPARE_1");
}

fn analyze_fuse(data: &[u8]) {
    println!("\n  --- Fuse Analysis ---");
    // FUSE_FUSECTRL_0 at offset 0x00 (relative to 0x7000F800)
    print_reg(data, "FUSE", 0x00, "FUSECTRL");
    // FUSE_FUSEDATA0..7 at +0x0C, +0x10, etc
    for i in 0..8 {
        print_reg(data, "FUSE", 0x0C + i * 4, &format!("FUSEDATA{}", i));
    }
    // FUSE_SECURITY_MODE at various offsets
    // Production mode fuse
    if data.len() >= 0x1C {
        let fd3 = u32::from_le_bytes(data[0x18..0x1C].try_into().unwrap());
        println!("    FUSEDATA3 boot_security bits: 0x{:08x}", fd3);
    }
}

fn analyze_bsev(data: &[u8]) {
    println!("\n  --- BSEV (Security Engine) Analysis ---");
    // BSEV registers start at 0x60011000
    // BSEV_CMDQUE_CONTROL = +0x00
    print_reg(data, "BSEV", 0x00, "CMDQUE_CONTROL");
    // BSEV_INTR_STATUS = +0x18
    print_reg(data, "BSEV", 0x18, "INTR_STATUS");
    // BSEV_BSE_CONFIG = +0x44
    print_reg(data, "BSEV", 0x44, "BSE_CONFIG");
    // BSEV_SECURE_CONFIG = +0x80 region
    if data.len() >= 0x84 {
        print_reg(data, "BSEV", 0x80, "SECURE_DEST_ADDR");
        print_reg(data, "BSEV", 0x84, "SECURE_INPUT_SELECT");
    }
    // Check if DMA engine looks available
    if data.len() >= 4 {
        let ctrl = u32::from_le_bytes(data[0..4].try_into().unwrap());
        if ctrl == 0 || ctrl == 0xFFFFFFFF {
            println!("    BSEV CMDQUE_CONTROL = 0x{:08x} — engine may be disabled/locked", ctrl);
        } else {
            println!("    BSEV engine appears active (CMDQUE_CONTROL=0x{:08x})", ctrl);
        }
    }
}

fn kttttt(tcp: &mut TcpStream) {
    std::fs::create_dir_all("dumps").unwrap();

    // === Phase 0: Connectivity & cmd 17 diagnostics ===
    println!("=== Phase 0: Diagnostics ===");
    println!("[*] Testing cmd 1 (kread_u32) baseline...");
    let nk = kread_u32(tcp, 0x80bee010);
    println!("    kread_u32(0x80bee010) = 0x{:08x} — cmd 1 OK", nk);

    // Tiny cmd 17 probe: read just 4 bytes from a known-good register
    // CLK_RST_CONTROLLER_RST_SOURCE (0x60006000) — always readable
    println!("[*] Testing cmd 17 with minimal 4-byte probe...");
    match io_read_retry(tcp, 0x6000_6000, 0x0, 4, 3) {
        Ok(data) => {
            let v = u32::from_le_bytes(data[..4].try_into().unwrap());
            println!("[+] cmd 17 probe OK: CLK_RST_SOURCE = 0x{:08x}", v);
        }
        Err(e) => {
            println!("[-] cmd 17 probe FAILED: {}", e);
            println!("    Trying alternative: phys_addr=0x60006000, offset=0, count=4");
            match io_read_retry(tcp, 0x6000_0000, 0x6000, 4, 2) {
                Ok(data) => {
                    let v = u32::from_le_bytes(data[..4].try_into().unwrap());
                    println!("[+] alt probe OK: 0x{:08x}", v);
                }
                Err(e2) => {
                    println!("[-] alt probe also FAILED: {}", e2);
                    println!("[*] Falling back to kread_u32-based dumps...");
                    kttttt_via_kread(tcp);
                    return;
                }
            }
        }
    }

    // === Phase 1: Register dumps (cmd 17) ===
    println!("\n=== Phase 1: Hardware Register Dumps ===");

    let ahb_data = io_dump_retry(tcp, 0x6000_0000, 0xC000, 0x100, "dumps/ahb_arb.bin");
    let sb_data = io_dump_retry(tcp, 0x6000_0000, 0xC200, 0x100, "dumps/secboot.bin");
    let bsev_data = io_dump_retry(tcp, 0x6001_0000, 0x1000, 0x100, "dumps/bsev.bin");
    let fuse_data = io_dump_retry(tcp, 0x7000_0000, 0xF800, 0x400, "dumps/fuse.bin");

    // === Phase 2: Analyze registers ===
    println!("\n=== Phase 2: Register Analysis ===");
    if let Some(ref d) = ahb_data { analyze_ahb(d); }
    if let Some(ref d) = sb_data { analyze_secboot(d); }
    if let Some(ref d) = fuse_data { analyze_fuse(d); }
    if let Some(ref d) = bsev_data { analyze_bsev(d); }

    // === Phase 3: Bypass strategy decision ===
    println!("\n=== Phase 3: Bypass Strategy ===");
    let mut strategy = Vec::new();

    if let Some(ref d) = sb_data {
        if d.len() >= 4 {
            let csr = u32::from_le_bytes(d[0..4].try_into().unwrap());
            let pirom_disable = (csr >> 4) & 1;
            let ns_lock = csr & 1;
            if pirom_disable == 0 {
                strategy.push("IROM not disabled by SB_CSR — direct cmd 17 read should work");
            } else if ns_lock == 0 {
                strategy.push("PIROM_DISABLE set but NS_LOCK clear — try clearing via cmd 18 io_write");
            } else {
                strategy.push("PIROM_DISABLE=1, NS_LOCK=1 — write-once lock active, software clear impossible");
            }
        }
    }

    if let Some(ref d) = ahb_data {
        if d.len() >= 0x80 {
            let usr_prot = u32::from_le_bytes(d[0x7C..0x80].try_into().unwrap());
            if usr_prot & 1 != 0 {
                strategy.push("AHB USR_PROTECT active — try clearing bit 0 via cmd 18");
            } else {
                strategy.push("AHB USR_PROTECT clear — not blocking");
            }
        }
    }

    if let Some(ref d) = bsev_data {
        if d.len() >= 4 {
            let ctrl = u32::from_le_bytes(d[0..4].try_into().unwrap());
            if ctrl != 0 && ctrl != 0xFFFFFFFF {
                strategy.push("BSEV engine appears active — DMA bypass may be possible");
            } else {
                strategy.push("BSEV engine looks disabled — DMA bypass unlikely");
            }
        }
    }

    if strategy.is_empty() {
        println!("  [?] Not enough register data to determine strategy");
    } else {
        for s in &strategy {
            println!("  -> {}", s);
        }
    }

    // === Phase 4: Attempt IROM read ===
    println!("\n=== Phase 4: IROM Probe (0xFFF00000) ===");
    println!("[*] Attempting 4-byte IROM probe...");
    match io_read_retry(tcp, 0xFFF0_0000, 0x0, 4, 2) {
        Ok(data) => {
            let v = u32::from_le_bytes(data[..4].try_into().unwrap());
            println!("[+] IROM+0x00 = 0x{:08x}", v);
            if v == 0x00000000 || v == 0xFFFFFFFF || v == 0xd0d0caca {
                println!("    WARNING: value looks like bus error / unmapped — IROM may be protected");
            } else {
                println!("    Looks like real data! Proceeding with full 64KB dump...");
                dump_irom_chunked(tcp);
            }
        }
        Err(e) => {
            println!("[-] IROM probe failed: {}", e);
            println!("    IROM is likely access-protected at the hardware level");
        }
    }

    println!("\n[DONE]");
}

fn dump_irom_chunked(tcp: &mut TcpStream) {
    let base = 0xFFF0_0000u32;
    let total_sz = 0x10000u32;
    let filename = "dumps/irom.bin";
    let chunk = 1024u32;
    let mut all_data = Vec::new();

    for off in (0..total_sz).step_by(chunk as usize) {
        let remaining = std::cmp::min(chunk, total_sz - off);
        match io_read_retry(tcp, base, off, remaining, 2) {
            Ok(data) => {
                all_data.extend_from_slice(&data);
                if off % 0x4000 == 0 {
                    println!("  0x{:x}/0x{:x} ({:.0}%)", off, total_sz, off as f64 / total_sz as f64 * 100.0);
                }
            }
            Err(e) => {
                println!("  [-] FAIL at offset 0x{:x}: {}", off, e);
                break;
            }
        }
    }
    if !all_data.is_empty() {
        std::fs::write(filename, &all_data).unwrap();
        println!("[+] {} ({} bytes / {} expected)", filename, all_data.len(), total_sz);
    }
}

// Fallback: dump registers word-by-word via cmd 1 (kread_u32)
// Slower but uses the proven-working command
fn kttttt_via_kread(tcp: &mut TcpStream) {
    std::fs::create_dir_all("dumps").unwrap();
    println!("\n=== Fallback: Register dumps via kread_u32 (cmd 1) ===");
    println!("    NOTE: cmd 1 reads kernel virtual memory, not physical I/O.");
    println!("    These addresses must be kernel-mapped. If not, we'll get garbage.");

    // On Tegra/WinCE, hardware registers are typically mapped at their physical
    // addresses in the kernel's static mapping table. Try reading them.
    let regions: Vec<(u32, u32, &str)> = vec![
        (0x6000C000, 0x100, "dumps/ahb_arb_kread.bin"),
        (0x6000C200, 0x100, "dumps/secboot_kread.bin"),
        (0x60011000, 0x100, "dumps/bsev_kread.bin"),
        (0x7000F800, 0x400, "dumps/fuse_kread.bin"),
    ];

    for (addr, sz, filename) in &regions {
        println!("[*] kread 0x{:08x} ({}B) -> {}", addr, sz, filename);
        let mut data = Vec::new();
        let mut failed = false;
        for off in (0..*sz).step_by(4) {
            let val = kread_u32(tcp, addr + off);
            // Check for likely unmapped address (all F's or data abort sentinel)
            if off == 0 && (val == 0xFFFFFFFF || val == 0xd0d0caca) {
                println!("    First word = 0x{:08x} — likely not kernel-mapped, skipping", val);
                failed = true;
                break;
            }
            data.extend_from_slice(&val.to_le_bytes());
        }
        if !failed && !data.is_empty() {
            std::fs::write(filename, &data).unwrap();
            println!("[+] {} ({} bytes)", filename, data.len());
            // Print first 32 bytes
            for i in (0..std::cmp::min(data.len(), 32)).step_by(4) {
                let v = u32::from_le_bytes(data[i..i+4].try_into().unwrap());
                print!("  +0x{:02x}: 0x{:08x}", i, v);
                if (i/4) % 4 == 3 { println!(); }
            }
            println!();
        }
    }
}

fn kquit(tcp: &mut TcpStream) {
    let mut c = Vec::new();
    c.push(11u8);
    c.resize(32, 0);
    tcp.write_all(&c).unwrap();

    // let mut iubu = [0u8; 32];
    // tcp.read(&mut iubu).unwrap();
    // assert_eq!(iubu[0], 1);
    // let val = u32::from_le_bytes(iubu[1..][..4].try_into().unwrap());
    // val
}

fn kread_u16(tcp: &mut TcpStream, addr: u32) -> u16 {
    (kread_u32(tcp, addr) & 0xFFFF) as u16
}

#[derive(Debug, Serialize)]
struct Proc {
    next: u32,
    last: u32,
    id: u32,
    thread_next: u32,
    thread_last: u32,
    name: String,
    base: u32,

    mods: Vec<Module>,
    thrds: Vec<Thread>,
}

#[derive(Debug, Serialize)]
struct Thread {
    next: u32,
    base: u32,
}
fn preadstr(tcp: &mut TcpStream, p: u32, addr: u32) -> String {
    let mut name = Vec::new();
    let mut off = 2;
    let mut c = (pread32(tcp, p, addr).unwrap() & 0xFF) as u16;
    while c != 0 {
        name.push(c);
        c = (pread32(tcp, p, addr + off).unwrap() & 0xFF) as u16;
        off += 2;
    }
    let name = String::from_utf16(&name).unwrap();

    name
}

fn kreadstr(tcp: &mut TcpStream, addr: u32) -> String {
    let mut name = Vec::new();
    let mut off = 2;
    let mut c = kread_u16(tcp, addr);
    while c != 0 {
        name.push(c);
        c = kread_u16(tcp, addr + off);
        off += 2;
    }
    let name = String::from_utf16(&name).unwrap();

    name
}

#[derive(Debug, Serialize)]
struct Module {
    next: u32,
    name: String,
}

fn read_module(tcp: &mut TcpStream, mod_ptr: u32) -> Module {
    let next = kread_u32(tcp, mod_ptr+0x0);
    let oe = mod_ptr+0x84;
    let pfn = mod_ptr+0x80;
    let zone = mod_ptr+0x7c;
    let zone2 = mod_ptr+0x78;
    let dbg = mod_ptr+0x74;
    let nname2 = kread_u32(tcp, mod_ptr+0x70);
    let name = kreadstr(tcp, nname2);
    // println!("{n}");

    // let oe_lpname = kread_u32(tcp, oe+0xc);
    // let toc = kread_u32(tcp, oe+0x0);
    // let mut name = "".to_string();
    // if oe_lpname != 0 {
    //     name = kreadstr(tcp, oe_lpname);
    // } else {
    //     let toc_Addr = kread_u32(tcp, toc+0x10);
    //     name = kreadstr(tcp, toc_Addr);
    // }
    // println!("mod = {mod_next:x}, mod2={mod_ptr:x}, oe={oe:x}, tocptr={toc:x}, name={oe_lpname:x}, oe_name={name}");

    Module{
        next,
        name
    }
}

fn read_thrd(tcp: &mut TcpStream, mod_ptr: u32) -> Thread {
    let next = kread_u32(tcp, mod_ptr+0x0);
    let base = kread_u32(tcp, mod_ptr+0x20);
    // let oe = mod_ptr+0x84;
    // let pfn = mod_ptr+0x80;
    // let zone = mod_ptr+0x7c;
    // let zone2 = mod_ptr+0x78;
    // let dbg = mod_ptr+0x74;
    // let nname2 = kread_u32(tcp, mod_ptr+0x70);
    // let name = kreadstr(tcp, nname2);
    // println!("{n}");

    // let oe_lpname = kread_u32(tcp, oe+0xc);
    // let toc = kread_u32(tcp, oe+0x0);
    // let mut name = "".to_string();
    // if oe_lpname != 0 {
    //     name = kreadstr(tcp, oe_lpname);
    // } else {
    //     let toc_Addr = kread_u32(tcp, toc+0x10);
    //     name = kreadstr(tcp, toc_Addr);
    // }
    // println!("mod = {mod_next:x}, mod2={mod_ptr:x}, oe={oe:x}, tocptr={toc:x}, name={oe_lpname:x}, oe_name={name}");

    Thread{
        next,
        base,
    }
}


fn read_proc(tcp: &mut TcpStream, proc: u32) -> Proc {
    let next = kread_u32(tcp, proc);
    let last = kread_u32(tcp, proc+4);
    let id = kread_u32(tcp, proc+0xc);
    let thread_next = kread_u32(tcp, proc+0x10);
    let thread_last = kread_u32(tcp, proc+0x14);
    let base = kread_u32(tcp, proc+0x18);
    let name_ptr = kread_u32(tcp, proc+0x20);
    let name = kreadstr(tcp, name_ptr);


    let mut thrds = Vec::new();
    let mut cur_thrd_ptr = thread_next;
loop {
    let m = read_thrd(tcp, cur_thrd_ptr);
    // println!("{m:?}");
    cur_thrd_ptr = m.next;
    thrds.push(m);
    if cur_thrd_ptr == thread_next {
        break;
    }
}

   let mod_next = kread_u32(tcp, proc+0x108); // _MODULELIST
   let mod_ptr = kread_u32(tcp, mod_next+8); // _MODULE




    let mut mods = Vec::new();

    let mut cur_mod_ptr = mod_ptr;
    loop {
        let m = read_module(tcp, cur_mod_ptr);
        println!("{m:?}");
        cur_mod_ptr = m.next;
        mods.push(m);
        if cur_mod_ptr == mod_ptr {
            break;
        }
    }




    Proc {
        next,
        last,
        id,
        name,
        thread_next,
        thread_last,
        thrds,
        base,
        mods,
    }
}

fn wait_for_proc(tcp: &mut TcpStream, proc: u32, n: &String) -> (u32, u32) {
    let mut nk = proc;
    loop {
        let next = kread_u32(tcp, nk);

        let name_ptr = kread_u32(tcp, nk + 0x20);
        let name = kreadstr(tcp, name_ptr);
        if name.contains(n) {
            let id = kread_u32(tcp, nk+0xc);
            return (nk, id);
        }
        nk = next;
    }
}
pub mod zunecom {


        include!(concat!(env!("OUT_DIR"), "/zunecom.rs"));

}


fn lsdir(tcp: &mut TcpStream, base: &String) -> Option<Vec<(String, bool)>> {
    let cmd = CommandReq {
        cmd: CommandType::CmdLsdir.into(),
        payload: Some(crate::zunecom::command_req::Payload::Lsdir(
            PayloadLsdir {
                path: format!("{base}\\*")
            }
        ))
    };
    let buf = cmd.encode_to_vec();

    let mut c = Vec::new();
    c.push(16);
    c.extend_from_slice(buf.as_slice());
    tcp.write_all(&c).unwrap();

    let mut total = Vec::new();
    let mut out = Vec::new();

    loop {
        let mut iubu = [0u8; 0x808];
        let sz = match tcp.read(&mut iubu) {
            Ok(sz) => sz,
            Err(_) => return None,
        };
        let iubu = &iubu[..sz];
        total.extend_from_slice(iubu);
        // println!("{sz:x}");
        let resp = CommandResp::decode(total.as_slice());
        // println!("{resp:?}");


        if let Ok(resp) = resp {
            if let Some(p) = resp.payload {
                if let crate::zunecom::command_resp::Payload::Lsdir(ls) = p {
                    assert!(ls.path.len() < 270);
                    for p in ls.path {
                        out.push((format!("{base}\\{}", p.path), p.is_dir));
                    }
                    break;
                } else {
                    panic!();
                }
            } else {
                panic!()
            }
        } else {
            println!("what {:?}", resp);
            std::fs::write("err", &total).unwrap()
        }
    }

    // println!("{out:?}");

    Some(out)
}

fn dlfile(tcp: &mut TcpStream, base: &String) -> Option<Vec<u8>> {
    let cmd = CommandReq {
        cmd: CommandType::CmdRdfile.into(),
        payload: Some(crate::zunecom::command_req::Payload::Rdfile(
            PayloadRdfile {
                path: base.clone(),
            }
        ))
    };
    let buf = cmd.encode_to_vec();
    // println!("{}", buf.len());

    let mut c = Vec::new();
    c.push(16);
    c.extend_from_slice(buf.as_slice());
    tcp.write_all(&c).unwrap();

    let mut out = Vec::new();

    let mut total = Vec::new();

    let mut totalsz = 0xFFFFu32; // so we detect dropped first pkt with sz

    let mut err_cnt = 0;
    let mut i = 0;

    let mut bar = ProgressBar::new(1000);
    bar.set_style(ProgressStyle::with_template ("{msg}: {wide_bar} {pos}/{len} {eta}").unwrap());
    bar.set_message(format!("{}: ", base));

    let mut iubu = [0u8; 0x1000];

    loop {
        if err_cnt > 10 {
            return None;
        }

        let sz = match tcp.read(&mut iubu) {
            Ok(sz) => sz,
            Err(e) => {
                error!("tmp err: {e}");
                return None;
            }
        };
        let iubu = &iubu[..sz];
        total.extend_from_slice(iubu);
        // println!("{iubu:?}");

        if sz == 0 {
            warn!("Zero sized read");
            std::thread::sleep(std::time::Duration::from_millis(100));
            err_cnt += 1;
            continue;
        }

        //println!("{sz:x}");
        // println!("{iubu:?}");
        // std::fs::write("a", iubu).unwrap();

        let resp = CommandResp::decode(total.as_slice());
        // println!("{resp:?}");


        if let Ok(resp) = resp {
            i += 1;

            if resp.cmd == ResType::RspRdfileEof as i32 {
                // If file is zero sized, we will get no payloads, just an eof
                if i > 1 {
                    if out.len() != totalsz as usize {
                        error!("WRONG SZ  {base}: {}, {}, {i}", out.len(), totalsz);
                        return None;
                    }
                }
                if out.len() == 0 {
                    error!("zsf: {base}");
                    return Some(out);
                }
                break;
            } else if let Some(p) = &resp.payload {
                if let crate::zunecom::command_resp::Payload::Rdfile(f) = p {
                    if totalsz == 0xFFFFu32 {
                        totalsz = f.fullsz;
                        bar.set_length(totalsz as _);
                    } else {
                        if totalsz != f.fullsz {
                            error!("totalsz change!! {} -> {}", totalsz, f.fullsz);
                            return None;
                        }
                    }

                    out.extend_from_slice(&f.data);
                    bar.set_position(out.len() as _);

                    total = total[resp.encoded_len()..].to_vec();

                    // println!("{} / {}", out.len(), totalsz);

                } else {
                    panic!("what: {p:?}");
                }
            } else {
                error!("Unknonwn pkt");
                return None;
                // panic!()
            }

            // println!("{resp:?}");
        } else {
            if iubu[0] == 0xCD {
                std::fs::write("err", iubu).unwrap();
                error!("GOT ERR MESG");
                return None;
            }
        }
    }

    Some(out)
}

fn main() {
    tracing_subscriber::fmt::fmt().init();

    let mut tcp = TcpStream::connect(("192.168.0.67", 1337)).unwrap();
    tcp.set_read_timeout(Some(Duration::from_secs(600))).unwrap(); // 10min for large transfers
    tcp.set_nodelay(true).unwrap();

    loop {
        let mut iubu = [0u8; 8];
        match tcp.read(&mut iubu) {
            Ok(sz) => {
                println!("{:?}", String::from_utf8(iubu.to_vec()));
                break;
            },
            Err(e) => {
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
        }
    }

    let nk = kread_u32(&mut tcp, 0x80bee010);
    println!("{nk:x}");

    if true {
        // Cmd 21: single-shot 64KB IROM dump with 256-byte send chunks
        println!("=== IROM Dump via Cmd 21 (single mapping, 256B sends) ===");
        std::fs::create_dir_all("dumps").unwrap();

        let mut c = vec![21u8];
        c.resize(32, 0);
        tcp.write_all(&c).unwrap();

        let mut resp = [0u8; 32];
        tcp.read_exact(&mut resp).unwrap();

        if resp[0] != 21 {
            println!("[-] cmd 21 not recognized (got 0x{:02x})", resp[0]);
            return;
        }
        if resp[1] != 1 {
            println!("[-] IROM mapping failed (status=0x{:02x})", resp[1]);
            return;
        }

        let first_word = u32::from_le_bytes(resp[2..6].try_into().unwrap());
        println!("[+] IROM mapped, first word: 0x{:08x}", first_word);
        println!("[*] Receiving 64KB (256-byte sends, ~4 minutes)...");

        let mut irom_data = Vec::new();
        let target = 0x10000usize;
        let mut buf = [0u8; 4096];
        loop {
            match tcp.read(&mut buf) {
                Ok(0) => {
                    println!("    Connection closed at 0x{:x}", irom_data.len());
                    break;
                }
                Ok(n) => {
                    irom_data.extend_from_slice(&buf[..n]);
                    if irom_data.len() % 0x1000 < n || irom_data.len() >= target {
                        println!("    0x{:x}/0x{:x} ({:.0}%)",
                            irom_data.len(), target,
                            irom_data.len() as f64 / target as f64 * 100.0);
                    }
                    // Save progress
                    if irom_data.len() % 0x4000 < n {
                        std::fs::write("dumps/irom_partial.bin", &irom_data).unwrap();
                    }
                    if irom_data.len() >= target {
                        break;
                    }
                }
                Err(e) => {
                    println!("    [-] Read error at 0x{:x}: {}", irom_data.len(), e);
                    break;
                }
            }
        }

        irom_data.truncate(target);

        println!("\n=== Result ===");
        println!("  Received: {} / {} bytes", irom_data.len(), target);
        if irom_data.len() >= 4 {
            let first = u32::from_le_bytes(irom_data[..4].try_into().unwrap());
            let nonzero = irom_data.iter().filter(|&&b| b != 0).count();
            println!("  IROM[0x0000] = 0x{:08x}", first);
            println!("  Non-zero bytes: {}/{}", nonzero, irom_data.len());
            std::fs::write("dumps/irom.bin", &irom_data).unwrap();
            println!("[+] dumps/irom.bin written ({} bytes)", irom_data.len());
        } else {
            println!("[-] Not enough data received");
        }

        println!("\n[DONE]");
        return;
    }

    if false {
        // Old cmd 21 approach (streaming)
        println!("=== IROM Dump via Cmd 21 (device-side BSEV DMA) ===");
        let mut c = vec![21u8];
        c.resize(32, 0);
        tcp.write_all(&c).unwrap();

        // Read 32-byte status
        let mut resp = [0u8; 32];
        tcp.read_exact(&mut resp).unwrap();

        if resp[0] != 21 {
            println!("[-] cmd 21 not recognized (got 0x{:02x}). Payload needs rebuild.", resp[0]);
            return;
        }

        let status = resp[1];
        println!("  Status: 0x{:02x}", status);
        println!("  Mappings: clk={} bsev={} bsea={} iram={}",
            resp[2], resp[3], resp[4], resp[5]);

        let bsev_probe = u32::from_le_bytes(resp[7..11].try_into().unwrap());
        println!("  BSEV alive: {} (probe=0x{:08x})", resp[6], bsev_probe);

        let irom_mapped = resp[11];
        let irom_first = u32::from_le_bytes(resp[12..16].try_into().unwrap());
        println!("  IROM direct map: {} (first word=0x{:08x})", irom_mapped, irom_first);

        if status == 1 || status == 2 || status == 3 {
            let method = match status {
                1 => "BSEV DMA",
                2 => "direct NKCreateStaticMapping read",
                3 => "BSEA DMA",
                _ => "unknown",
            };
            println!("[+] IROM dump succeeded via {}!", method);
            println!("[*] Receiving 64KB (this takes a while — byte-by-byte kreadb)...");

            let mut irom_data = Vec::new();
            let target = 0x10000usize;
            let mut buf = [0u8; 4096];
            while irom_data.len() < target {
                match tcp.read(&mut buf) {
                    Ok(0) => {
                        println!("    [-] Connection closed at {}/{}",
                            irom_data.len(), target);
                        break;
                    }
                    Ok(n) => {
                        irom_data.extend_from_slice(&buf[..n]);
                        if irom_data.len() % 0x1000 < n || irom_data.len() >= target {
                            println!("    0x{:x}/0x{:x} ({:.0}%)",
                                irom_data.len(), target,
                                irom_data.len() as f64 / target as f64 * 100.0);
                        }
                    }
                    Err(e) => {
                        println!("    [-] Read error at {}/{}: {}",
                            irom_data.len(), target, e);
                        break;
                    }
                }
            }
            irom_data.truncate(target);

            if irom_data.len() < 4 {
                println!("[-] Got only {} bytes — not enough data", irom_data.len());
                return;
            }

            // Validate
            let first_word = u32::from_le_bytes(irom_data[..4].try_into().unwrap());
            let last_word = if irom_data.len() >= 0x10000 {
                u32::from_le_bytes(irom_data[0xFFFC..].try_into().unwrap())
            } else { 0 };
            println!("  IROM[0x0000] = 0x{:08x}", first_word);
            println!("  IROM[0xFFFC] = 0x{:08x}", last_word);

            // Check it's not all zeros or all FF
            let nonzero = irom_data.iter().filter(|&&b| b != 0).count();
            let non_ff = irom_data.iter().filter(|&&b| b != 0xFF).count();
            println!("  Non-zero bytes: {}/65536", nonzero);
            println!("  Non-0xFF bytes: {}/65536", non_ff);

            std::fs::create_dir_all("dumps").unwrap();
            std::fs::write("dumps/irom.bin", &irom_data).unwrap();
            println!("[+] dumps/irom.bin written (65536 bytes)");
        } else {
            // DMA failed, print diagnostics
            let bsev_status = u32::from_le_bytes(resp[16..20].try_into().unwrap());
            let iram_check = u32::from_le_bytes(resp[20..24].try_into().unwrap());
            println!("  BSEV DMA status: 0x{:08x}", bsev_status);
            println!("  IRAM after DMA: 0x{:08x}", iram_check);

            if resp.len() >= 28 {
                let bsea_status = u32::from_le_bytes(resp[24..28].try_into().unwrap());
                let iram_check2 = u32::from_le_bytes(resp[28..32].try_into().unwrap());
                println!("  BSEA DMA status: 0x{:08x}", bsea_status);
                println!("  IRAM after BSEA: 0x{:08x}", iram_check2);
            }
            println!("[-] All IROM dump approaches failed");
        }

        println!("\n[DONE]");
        return;
    }

    if false {
        let mut procs = Vec::new();

        let mut proc_addr = nk;
        loop {
            let proc = read_proc(&mut tcp, proc_addr);
            println!("{proc:?}");
            proc_addr = proc.next;
            procs.push(proc);
            if proc_addr == nk {
                break;
            }
        }

        let o = serde_json::to_string_pretty(&procs).unwrap();
        std::fs::write("out.json", &o).unwrap();
    }


    fn do_stuff(tcp: &mut TcpStream, p: String) {
        let more_files;
        loop {
            info!("[*] ls {}", &p);
            let tmp_more_files = lsdir(tcp, &p);
            if let Some(tmp_more_files) = tmp_more_files {
                info!("[*] ls {:?}", tmp_more_files);
                more_files = tmp_more_files;
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        for (f, dir) in more_files {

            let pth = PathBuf::from(format!("out/{}", f).replace("\\", "/"));

            if dir {
                info!("[*] rec {f}");
                std::fs::create_dir_all(&pth).unwrap();
                do_stuff(tcp, f);
                continue;
            } else {
                let dat;
                loop {
                    info!("[*] dl {f}");
                    let d = dlfile(tcp, &f);
                    if let Some(d) = d {
                        dat = d;
                        break
                    }
                    std::thread::sleep(Duration::from_millis(100));
                }

                std::fs::write(&pth, &dat).unwrap();
                info!("[*] {f}: {}", dat.len());
            }
        }
    }
    std::fs::create_dir_all("out/gametitle").unwrap();
    do_stuff(&mut tcp, "\\gametitle".to_string());

    // std::fs::create_dir_all("out/gametitle/584E07D1/Content/Puzzles").unwrap();
    // do_stuff(&mut tcp, "\\gametitle\\584E07D1\\Content\\Puzzles".to_string());

    info!("[DONE]");

    return;


    // let gs = procs.iter().find(|p| p.name.contains("ZIE")).unwrap();
    // kkill(&mut tcp, gs.id);
    //
    // kquit(&mut tcp);
    // return;

return;

    /*

    if false {


        // let gs = procs.iter().find(|p| p.name.contains("compositor")).unwrap();
        // let (gs, id) = wait_for_proc(&mut tcp, nk, &"gemstone".to_string());
        let (gs, id) = wait_for_proc(&mut tcp, nk, &"ZIE".to_string());


        // let gs = procs.iter().find(|p| p.name.contains("ZIE")).unwrap();
        let pr = openproc(&mut tcp, id);
        let k = dbgcon(&mut tcp, id);
        if k == 0{
            kquit(&mut tcp);
            return;
        }
        println!("d = {k}");

        let bp = [
            // (0x4036dc44, 0xe1a02000, 0xe0d230b2, "wcslen", Box::new(|r: &Reg, tcp: &mut TcpStream, pr: u32| {
            //     let r0 = preadstr(tcp, pr, r.r0);
            //     println!("wsclen({r0}, {r:x?})");
            // }))

                (0x40342d48, 0xe92d4070, 0xe24dd014, "commodem", Box::new(|r: &Reg, tcp: &mut TcpStream, pr: u32| {
                panic!("WTF({r:x?})");
            }))

        ];

        loop {
            if let Some((evt, p, t)) = dbgwait(&mut tcp) {

                match evt {
                    // create proc
                    3 => {
                        // pwrite32(&mut tcp, pr, 0x40336b64, 0xe7f001f0); // file
                        // pwrite32(&mut tcp, pr, 0x403378e8, 0xe7f001f0); //regkey
                        //pwrite32(&mut tcp, pr, 0x4033773c, 0xe7f001f0); //regcreate
                        for p in &bp {
                            pwrite32(&mut tcp, pr, p.0, 0xe7f001f0);
                        }

                         pwrite32(&mut tcp, pr, 0x40eeaf14, 0xe7f001f0); // jscript!typeof_call
                         pwrite32(&mut tcp, pr, 0x4035a514, 0xe7f001f0); // core!all_args_gadget
                         pwrite32(&mut tcp, pr, 0x40332b88, 0xe7f001f0); // core!virtual_prot
                         pwrite32(&mut tcp, pr, 0x40332bb4, 0xe7f001f0); // core!virtual_prot[ret]
                         pwrite32(&mut tcp, pr, 0x40331c14, 0xe7f001f0); // core!create_proc_w
                    }
                    //exit thread
                    4 => {}
                    //bkpt / exception
                    1 => {
                        let r = getregs(&mut tcp, t);

                        if r.pc == 0x40336b64 { // open file
                            let s = preadstr(&mut tcp, pr, r.r0);
                            println!("CreateFileW({s}, {r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe92d4070);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x40336b64 + 4{
                            println!("cfw 2");
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe24dd00c);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc-4, 0xe7f001f0);
                        } else if r.pc == 0x403378e8 { // reg open
                            let s = preadstr(&mut tcp, pr, r.r1);
                            println!("RegOpenKeyEx({s}, {r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe92d4010);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x403378e8+4 {
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe24dd004);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc - 4, 0xe7f001f0);
                        } else if r.pc == 0x4033773c { // reg open
                            let s = preadstr(&mut tcp, pr, r.r1);
                            println!("RegCreateKeyExW({s}, {r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe92d41f0);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x4033773c+4 {
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe24dd014);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc-4, 0xe7f001f0);
                        } else if r.pc == 0x40332bb4 {
                            println!("VirtualProtect[ret]({r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe12fff1e);
                        //NOTE: not put back because its a LR
                        } else if r.pc == 0x40331c14 {
                            println!("CreateProcW({r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe92d41f0);
                        //NOTE: not put back because its a LR


                        } else if r.pc == 0x40332b88 {
                            println!("VirtualProtect({r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe52de004);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x40332b88 + 4 {
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe24dd004);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc - 4, 0xe7f001f0);
                        } else if r.pc == 0x4035a514 { // gadget
                            println!("magic_gadget({r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe1a0d000);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x4035a514 + 4 {
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe99dffff);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc - 4, 0xe7f001f0);
                        } else if r.pc == 0x40eeaf14 { // reg open
                            println!("typeof({r:x?})");

                            // rm bk
                            pwrite32(&mut tcp, pr, r.pc, 0xe12fff13);
                            // add bk on pc+4#
                            pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                        } else if r.pc == 0x40eeaf14 + 4 {
                            // rm bk pc +4
                            pwrite32(&mut tcp, pr, r.pc, 0xe3500000);
                            // add bkpt1 back
                            pwrite32(&mut tcp, pr, r.pc - 4, 0xe7f001f0);
                        } else {
                            let mut h = false;

                            for p in &bp {
                                if r.pc == p.0 {
                                    (p.4)(&r, &mut tcp, pr);

                                    // rm bk
                                    pwrite32(&mut tcp, pr, r.pc, p.1);
                                    // add bk on pc+4#
                                    pwrite32(&mut tcp, pr, r.pc + 4, 0xe7f001f0);
                                    h = true;
                                    break;
                                } else if r.pc == p.0+4 {
                                    // rm bk pc +4
                                    pwrite32(&mut tcp, pr, r.pc, p.2);
                                    // add bkpt1 back
                                    pwrite32(&mut tcp, pr, r.pc - 4, 0xe7f001f0);
                                    h = true;
                                    break;
                                }
                            }

                            if !h {
                                println!("BR not here @ {:x?}", r);
                            }
                        }
                    }
                    // load dll
                    6 => {
                    }
                    _ => {
                        println!("unk evt {evt:x} {p:x} {t:x}");
                    }
                }
                println!("[{}] dbg: {evt:x} {p:x} {t:x}", unsafe { _rdtsc()});
                dbgcont(&mut tcp, p, t);

            }
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    // let gs = procs.iter().find(|p| p.name.contains("gemstone")).unwrap();
    let gs = procs.iter().find(|p| p.name.contains("ZIE")).unwrap();

    let k = openproc(&mut tcp, gs.id);
    println!("k = {k:x}");

    if true {
        let mut ok = Vec::new();
        let mut start = 0;
        let mut base = 0;
        for _ in 0..2000 {
            if pread32(&mut tcp, k, base).is_none() {
                if base != start + 0x1000 && start != 0 {
                    ok.push((start, base - 0x1000));
                    start = 0;
                }
            } else {
                if start == 0 {
                    start = base;
                }
            }

            base += 0x1000;
        }
        println!("ok = {:x?}", ok);
        std::fs::write("./mem.json", serde_json::to_string_pretty(&ok).unwrap()).unwrap();


        let mut cpy = Vec::new();
        for (base, end) in ok.iter() {
            cpy.clear();
            // let base: u32 = 0xa0000;
            // let end = 0xbd000;
            let l = (end - base) / 4;
            println!("Fetching {base:x} - {end:x}: {}", l);
            let bar = progression::Bar::new(l as _, progression::Config::cargo());
            for off in 0..l {
                if let Some(k) = pread32(&mut tcp, k, base + off * 4) {
                    cpy.extend_from_slice(k.to_le_bytes().as_slice());
                } else {
                    println!("rd fail @ {:x}", base + off * 4);
                }
                bar.inc(1);
            }
            std::fs::write(&format!("./gem-{base:x}-{end:x}.bin"), &cpy).unwrap();
        }
    }

    if false {
        let mut cpy = Vec::new();
        let base = 0x140000;
        let l = 0xe000/4;
        for off in 0..l {
            if let Some(k) = pread32(&mut tcp, k, base + off*4) {
                cpy.extend_from_slice(k.to_le_bytes().as_slice());
            } else {
                println!("rd fail @ {:x}", base + off * 4);
            }
        }

        let needl = "Bootloader".encode_utf16().flat_map(|b| b.to_le_bytes()).collect::<Vec<_>>();
        if let Some(pos) = cpy.windows(needl.len()).position(|w| w == &needl) {
            println!("Boot @ {:x}", base as usize + pos);

            pwrite32(&mut tcp, k, base + pos as u32, 0x41004100);
        }
    }
*/

}

//todo: try dump via browser 9.1.15.62
//todo for 4k addr iram maybe need to enable with IRAMA
//AHB_ARBITRATION_USR_PROTECT_0
//CLK_ENB_IRAMD