// Minimal HTTP/1.0 server for serving the browser exploit payloads
// to the Zune HD's Internet Explorer browser.
//
// Usage: httpserv [port] [directory]
//   defaults: port=8080, directory=../browser_exploit

use std::env;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use flate2::write::GzEncoder;
use flate2::Compression;

/// Shared state for the reverse command channel.
/// PC submits commands via POST /cmd/submit, Zune polls GET /cmd/poll,
/// Zune posts results via POST /cmd/response, PC reads GET /cmd/result.
struct CmdQueue {
    pending: Option<Vec<u8>>,   // next command for the Zune to execute
    response: Option<Vec<u8>>,  // last response from the Zune
}

impl CmdQueue {
    fn new() -> Self {
        Self { pending: None, response: None }
    }
}

fn content_type(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html",
        Some("js") => "application/javascript",
        Some("css") => "text/css",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("bin") => "application/octet-stream",
        Some("json") => "application/json",
        _ => "application/octet-stream",
    }
}

fn read_body(_req: &str, buf: &[u8], n: usize, stream: &mut std::net::TcpStream) -> Vec<u8> {
    // Parse Content-Length from raw bytes (avoid UTF-8 lossy issues with binary bodies)
    let mut content_length: usize = 0;
    let header_str = String::from_utf8_lossy(&buf[..std::cmp::min(n, 1024)]);
    for line in header_str.lines() {
        if line.to_lowercase().starts_with("content-length:") {
            if let Ok(len) = line[15..].trim().parse() {
                content_length = len;
            }
        }
    }
    // Find \r\n\r\n in raw bytes
    let mut body = Vec::new();
    let mut hdr_end = 0;
    for i in 0..n.saturating_sub(3) {
        if buf[i] == b'\r' && buf[i+1] == b'\n' && buf[i+2] == b'\r' && buf[i+3] == b'\n' {
            hdr_end = i + 4;
            break;
        }
    }
    if hdr_end > 0 && hdr_end < n {
        body.extend_from_slice(&buf[hdr_end..n]);
    }
    while body.len() < content_length {
        let mut more = [0u8; 4096];
        match stream.read(&mut more) {
            Ok(0) => break,
            Ok(m) => body.extend_from_slice(&more[..m]),
            Err(_) => break,
        }
    }
    body
}

fn handle_request(mut stream: std::net::TcpStream, root: &Path, cmd_queue: &Arc<Mutex<CmdQueue>>) {
    let peer = stream.peer_addr().map(|a| a.to_string()).unwrap_or_default();

    let mut buf = [0u8; 4096];
    let n = match stream.read(&mut buf) {
        Ok(n) => n,
        Err(_) => return,
    };
    let req = String::from_utf8_lossy(&buf[..n]);

    // Parse first line: GET /path HTTP/1.0
    let first_line = req.lines().next().unwrap_or("");
    let parts: Vec<&str> = first_line.split_whitespace().collect();
    if parts.len() < 2 {
        return;
    }

    let method = parts[0];
    let raw_path = parts[1];

    println!("{} {} {}", peer, method, raw_path);

    // --- Reverse command channel ---

    // POST /cmd/submit — PC submits a command (32 bytes) for the Zune to execute
    if method == "POST" && raw_path == "/cmd/submit" {
        let body = read_body(&req, &buf, n, &mut stream);
        if body.len() >= 32 {
            let mut q = cmd_queue.lock().unwrap();
            println!("[cmd] Enqueued command: cmd={} subcmd={} ({} bytes)", body[0], body[1], body.len());
            q.pending = Some(body);
            // Don't clear response — let it persist until overwritten by next Zune response
            let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        } else {
            let _ = stream.write_all(b"HTTP/1.0 400 Bad Request\r\nContent-Length: 22\r\n\r\nNeed at least 32 bytes");
        }
        return;
    }

    // GET /cmd/poll — Zune polls for pending command
    if method == "GET" && raw_path == "/cmd/poll" {
        let mut q = cmd_queue.lock().unwrap();
        if let Some(cmd) = q.pending.take() {
            println!("[cmd] Zune polled -> delivering cmd={} ({} bytes)", cmd[0], cmd.len());
            let hdr = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                cmd.len()
            );
            let _ = stream.write_all(hdr.as_bytes());
            let _ = stream.write_all(&cmd);
        } else {
            let _ = stream.write_all(b"HTTP/1.0 204 No Content\r\nConnection: close\r\n\r\n");
        }
        return;
    }

    // POST /cmd/response — Zune uploads command response
    if method == "POST" && raw_path == "/cmd/response" {
        let body = read_body(&req, &buf, n, &mut stream);
        println!("[cmd] Zune responded: {} bytes", body.len());
        if body.len() >= 32 {
            // Print first 32 bytes as hex
            let hex: Vec<String> = body[..32].iter().map(|b| format!("{:02x}", b)).collect();
            println!("[cmd]   header: {}", hex.join(" "));
        }
        {
            let mut q = cmd_queue.lock().unwrap();
            q.response = Some(body);
        }
        let _ = stream.write_all(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK");
        return;
    }

    // GET /cmd/result — PC reads last response from Zune
    if method == "GET" && raw_path == "/cmd/result" {
        let q = cmd_queue.lock().unwrap();
        if let Some(resp) = &q.response {
            let hdr = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                resp.len()
            );
            let _ = stream.write_all(hdr.as_bytes());
            let _ = stream.write_all(resp);
        } else {
            let _ = stream.write_all(b"HTTP/1.0 204 No Content\r\nConnection: close\r\n\r\n");
        }
        return;
    }

    // Handle POST /upload/<filename> — device uploads data to PC
    if method == "POST" && raw_path.starts_with("/upload/") {
        let filename = &raw_path[8..]; // strip "/upload/"
        let filename = url_decode(filename);

        let body_data = read_body(&req, &buf, n, &mut stream);

        // Save to dumps directory
        let dumps_dir = root.join("../zuneslayer_debug/dumps");
        let _ = fs::create_dir_all(&dumps_dir);
        let save_path = dumps_dir.join(&filename);
        match fs::write(&save_path, &body_data) {
            Ok(()) => {
                println!("[+] Saved upload: {} ({} bytes) -> {}", filename, body_data.len(), save_path.display());
                let resp = format!(
                    "HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                );
                let _ = stream.write_all(resp.as_bytes());
            }
            Err(e) => {
                eprintln!("[-] Save failed: {}", e);
                let body = format!("Save failed: {}", e);
                let resp = format!(
                    "HTTP/1.0 500 Internal Server Error\r\nContent-Length: {}\r\n\r\n{}",
                    body.len(), body
                );
                let _ = stream.write_all(resp.as_bytes());
            }
        }
        return;
    }

    if method != "GET" {
        let body = "405 Method Not Allowed";
        let resp = format!(
            "HTTP/1.0 405 Method Not Allowed\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
        return;
    }

    // Quick 204 for favicon/icon requests
    if raw_path.contains("apple-touch-icon") || raw_path.contains("favicon.ico") {
        let _ = stream.write_all(b"HTTP/1.0 204 No Content\r\nConnection: close\r\n\r\n");
        return;
    }

    // Decode %xx sequences
    let decoded = url_decode(raw_path);
    let req_path = if decoded == "/" { "/index.html" } else { &decoded };

    // Prevent directory traversal
    let clean = req_path.trim_start_matches('/');
    let file_path = root.join(clean);
    if !file_path.starts_with(root) {
        let body = "403 Forbidden";
        let resp = format!(
            "HTTP/1.0 403 Forbidden\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        let _ = stream.write_all(resp.as_bytes());
        return;
    }

    // If it's a directory, try index.html or list files
    let file_path = if file_path.is_dir() {
        let idx = file_path.join("index.html");
        if idx.exists() {
            idx
        } else {
            // Directory listing
            let _ = serve_directory_listing(&mut stream, &file_path, req_path);
            return;
        }
    } else {
        file_path
    };

    // Serve orig.html at / to skip redirect round-trip
    let file_path = if req_path == "/index.html" || req_path == "/" {
        let exploit = root.join("orig.html");
        if exploit.exists() { exploit } else { file_path }
    } else {
        file_path
    };

    // Gzip disabled — IE Mobile 6 on WinCE may not decompress correctly
    // even though it sends Accept-Encoding: gzip
    let accepts_gzip = false;

    match fs::read(&file_path) {
        Ok(data) => {
            let ct = content_type(&file_path);
            let is_text = ct.starts_with("text/") || ct.contains("javascript") || ct.contains("json");

            // Gzip text content over 512 bytes (per optimization guide)
            if accepts_gzip && is_text && data.len() > 512 {
                let mut encoder = GzEncoder::new(Vec::new(), Compression::fast());
                let _ = encoder.write_all(&data);
                if let Ok(compressed) = encoder.finish() {
                    let saved = data.len() as i64 - compressed.len() as i64;
                    println!("  gzip: {} -> {} ({:+} bytes)", data.len(), compressed.len(), -saved);
                    let header = format!(
                        "HTTP/1.0 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nContent-Encoding: gzip\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                        ct,
                        compressed.len()
                    );
                    let _ = stream.write_all(header.as_bytes());
                    let _ = stream.write_all(&compressed);
                    return;
                }
            }

            // Uncompressed fallback
            let header = format!(
                "HTTP/1.0 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                ct,
                data.len()
            );
            let _ = stream.write_all(header.as_bytes());
            let _ = stream.write_all(&data);
        }
        Err(_) => {
            let body = "404 Not Found";
            let resp = format!(
                "HTTP/1.0 404 Not Found\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(resp.as_bytes());
        }
    }
}

fn serve_directory_listing(
    stream: &mut std::net::TcpStream,
    dir: &Path,
    req_path: &str,
) -> std::io::Result<()> {
    let mut body = format!(
        "<html><head><title>Index of {}</title></head><body><h1>Index of {}</h1><ul>\n",
        req_path, req_path
    );
    if req_path != "/" {
        body.push_str("<li><a href=\"..\">..</a></li>\n");
    }
    if let Ok(entries) = fs::read_dir(dir) {
        let mut names: Vec<_> = entries.filter_map(|e| e.ok()).collect();
        names.sort_by_key(|e| e.file_name());
        for entry in names {
            let name = entry.file_name().to_string_lossy().to_string();
            let suffix = if entry.path().is_dir() { "/" } else { "" };
            body.push_str(&format!(
                "<li><a href=\"{}/{}\">{}{}</a></li>\n",
                req_path.trim_end_matches('/'),
                name,
                name,
                suffix
            ));
        }
    }
    body.push_str("</ul></body></html>");

    let header = format!(
        "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body.as_bytes())?;
    Ok(())
}

fn url_decode(s: &str) -> String {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            if let Ok(val) = u8::from_str_radix(
                &String::from_utf8_lossy(&bytes[i + 1..i + 3]),
                16,
            ) {
                out.push(val);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).to_string()
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let port: u16 = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(8080);
    let dir = args
        .get(2)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("../browser_exploit"));

    let root = fs::canonicalize(&dir).unwrap_or_else(|_| {
        eprintln!("Error: directory '{}' not found", dir.display());
        std::process::exit(1);
    });

    let bind = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&bind).unwrap_or_else(|e| {
        eprintln!("Error: cannot bind {}: {}", bind, e);
        std::process::exit(1);
    });

    println!("Serving {} on http://0.0.0.0:{}", root.display(), port);
    println!("Point the Zune HD browser to http://<this-ip>:{}/", port);

    let cmd_queue = Arc::new(Mutex::new(CmdQueue::new()));

    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle_request(s, &root, &cmd_queue),
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
}
