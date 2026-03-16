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
use flate2::write::GzEncoder;
use flate2::Compression;

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

fn handle_request(mut stream: std::net::TcpStream, root: &Path) {
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

    // Handle POST /upload/<filename> — device uploads data to PC
    if method == "POST" && raw_path.starts_with("/upload/") {
        let filename = &raw_path[8..]; // strip "/upload/"
        let filename = url_decode(filename);

        // Parse Content-Length from headers
        let mut content_length: usize = 0;
        for line in req.lines().skip(1) {
            if line.to_lowercase().starts_with("content-length:") {
                if let Ok(len) = line[15..].trim().parse() {
                    content_length = len;
                }
            }
        }

        // Find the body (after \r\n\r\n)
        let mut body_data = Vec::new();
        if let Some(pos) = req.find("\r\n\r\n") {
            let header_len = pos + 4;
            // Body bytes already in our buffer
            if header_len < n {
                body_data.extend_from_slice(&buf[header_len..n]);
            }
        }

        // Read remaining body data
        while body_data.len() < content_length {
            let mut more = [0u8; 4096];
            match stream.read(&mut more) {
                Ok(0) => break,
                Ok(m) => body_data.extend_from_slice(&more[..m]),
                Err(_) => break,
            }
        }

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

    for stream in listener.incoming() {
        match stream {
            Ok(s) => handle_request(s, &root),
            Err(e) => eprintln!("accept error: {}", e),
        }
    }
}
