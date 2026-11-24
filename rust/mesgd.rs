//! mesgd transport client.
//!
//! One `Conn` == one wss connection == one path == one JWT; open several for
//! several topics or grants. `on`/`send` are the headline surface. Security is
//! opt-in: plain, signed (sig over body), or signed + sealed (body encrypted,
//! routable fields left in cleartext).
//!
//! The WebSocket client is built on `std::net` + `openssl::ssl` (already a
//! dependency — no tungstenite), implementing just the RFC 6455 client subset
//! mesgd needs: a json subprotocol with the bearer token as its second value,
//! masked text frames, and ping/pong.

use crate::PKI;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use openssl::rand::rand_bytes;
use openssl::ssl::{SslConnector, SslMethod};
use serde_json::Value;
use std::collections::HashMap;
use std::error::Error;
use std::io::{Read, Write};
use std::net::TcpStream;

trait Stream: Read + Write {}
impl<T: Read + Write> Stream for T {}

pub struct Options {
    pub pki: PKI,
    pub token: Option<String>,
    pub server_pub: Option<Value>,
    pub connector: Option<SslConnector>, // custom CA for tests; None uses system trust
}

#[derive(Default, Clone, Copy)]
pub struct SendOpts {
    pub sign: bool,
    pub seal: bool,
}

pub struct Conn {
    stream: Box<dyn Stream>,
    pki: PKI,
    server_pub: Option<Value>,
    handlers: HashMap<String, Box<dyn FnMut(Value)>>,
    buf: Vec<u8>,
}

/// Dials wss://host/path (path = subscription) and completes the upgrade.
pub fn connect(url: &str, opt: Options) -> Result<Conn, Box<dyn Error>> {
    let (scheme, rest) = url.split_once("://").ok_or("mesgd: bad url")?;
    let (authority, path) = match rest.split_once('/') {
        Some((a, p)) => (a.to_string(), format!("/{p}")),
        None => (rest.to_string(), "/".to_string()),
    };
    let (host, port) = match authority.split_once(':') {
        Some((h, p)) => (h.to_string(), p.parse::<u16>()?),
        None => (authority, if scheme == "wss" { 443 } else { 80 }),
    };
    let tcp = TcpStream::connect((host.as_str(), port))?;
    let stream: Box<dyn Stream> = if scheme == "wss" {
        let connector = match opt.connector {
            Some(c) => c,
            None => SslConnector::builder(SslMethod::tls())?.build(),
        };
        Box::new(connector.connect(&host, tcp)?)
    } else {
        Box::new(tcp)
    };

    let mut nonce = [0u8; 16];
    rand_bytes(&mut nonce)?;
    let proto = match &opt.token {
        Some(t) => format!("json, {t}"),
        None => "json".to_string(),
    };
    let mut conn = Conn {
        stream,
        pki: opt.pki,
        server_pub: opt.server_pub,
        handlers: HashMap::new(),
        buf: Vec::new(),
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {}\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Protocol: {proto}\r\n\r\n",
        STANDARD.encode(nonce)
    );
    conn.stream.write_all(req.as_bytes())?;
    conn.read_handshake()?;
    Ok(conn)
}

impl Conn {
    /// Registers a handler by message type; "*" is the catch-all.
    pub fn on<F: FnMut(Value) + 'static>(&mut self, typ: &str, handler: F) -> &mut Self {
        self.handlers.insert(typ.to_string(), Box::new(handler));
        self
    }

    /// Publishes `message` as one text frame. With sign/seal set, `message` must
    /// carry a "body"; `send` attaches "sig" over it and swaps "body" for an
    /// encrypted "enc", leaving routable fields visible.
    pub fn send(&mut self, message: Value, opt: SendOpts) -> Result<(), Box<dyn Error>> {
        let wire = self.frame(message, opt)?;
        self.write_frame(0x1, wire.as_bytes())
    }

    /// Reads one text frame, opens "enc" back into "body", and dispatches it.
    pub fn recv(&mut self) -> Result<(), Box<dyn Error>> {
        let payload = self.read_frame()?;
        self.dispatch(&payload)
    }

    pub fn close(&mut self) -> Result<(), Box<dyn Error>> {
        self.write_frame(0x8, &[])
    }

    fn frame(&self, mut message: Value, opt: SendOpts) -> Result<String, Box<dyn Error>> {
        if !opt.sign && !opt.seal {
            return Ok(serde_json::to_string(&message)?);
        }
        let body = serde_json::to_string(&message["body"])?;
        let obj = message.as_object_mut().ok_or("mesgd: message not an object")?;
        if opt.sign {
            obj.insert("sig".into(), Value::String(self.pki.sign(&body)?));
        }
        if opt.seal {
            obj.remove("body");
            let pub_jwk = self.server_pub.as_ref().ok_or("mesgd: seal requires server_pub")?;
            obj.insert("enc".into(), Value::String(PKI::seal(pub_jwk, &body)?));
        }
        Ok(serde_json::to_string(&message)?)
    }

    fn dispatch(&mut self, raw: &[u8]) -> Result<(), Box<dyn Error>> {
        let mut message: Value = serde_json::from_slice(raw)?;
        if let Some(enc) = message.get("enc").and_then(|v| v.as_str()).map(str::to_string) {
            let body: Value = serde_json::from_str(&self.pki.open(&enc)?)?;
            let obj = message.as_object_mut().unwrap();
            obj.remove("enc");
            obj.insert("body".into(), body);
        }
        let typ = message.get("type").and_then(|v| v.as_str()).unwrap_or("").to_string();
        let handler = if self.handlers.contains_key(&typ) {
            self.handlers.get_mut(&typ)
        } else {
            self.handlers.get_mut("*")
        };
        if let Some(h) = handler {
            h(message);
        }
        Ok(())
    }

    // ── RFC 6455 (client masks; server frames arrive unmasked) ──────────────

    fn read_handshake(&mut self) -> Result<(), Box<dyn Error>> {
        loop {
            if let Some(pos) = self.buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let status: Vec<u8> = self.buf[..pos].splitn(2, |&b| b == b'\r').next().unwrap().to_vec();
                self.buf.drain(..pos + 4);
                if !status.windows(5).any(|w| w == b" 101 ") {
                    return Err(format!("mesgd: upgrade failed: {}", String::from_utf8_lossy(&status)).into());
                }
                return Ok(());
            }
            let mut tmp = [0u8; 65536];
            let got = self.stream.read(&mut tmp)?;
            if got == 0 {
                return Err("mesgd: closed during handshake".into());
            }
            self.buf.extend_from_slice(&tmp[..got]);
        }
    }

    fn fill(&mut self, n: usize) -> Result<Vec<u8>, Box<dyn Error>> {
        while self.buf.len() < n {
            let mut tmp = [0u8; 65536];
            let got = self.stream.read(&mut tmp)?;
            if got == 0 {
                return Err("mesgd: connection closed".into());
            }
            self.buf.extend_from_slice(&tmp[..got]);
        }
        let rest = self.buf.split_off(n);
        Ok(std::mem::replace(&mut self.buf, rest))
    }

    fn read_frame(&mut self) -> Result<Vec<u8>, Box<dyn Error>> {
        let h = self.fill(2)?;
        let opcode = h[0] & 0x0F;
        let masked = h[1] & 0x80 != 0;
        let mut n = (h[1] & 0x7F) as usize;
        if n == 126 {
            let e = self.fill(2)?;
            n = u16::from_be_bytes([e[0], e[1]]) as usize;
        } else if n == 127 {
            let e = self.fill(8)?;
            n = u64::from_be_bytes(e[..8].try_into().unwrap()) as usize;
        }
        let mask = if masked { self.fill(4)? } else { Vec::new() };
        let mut payload = self.fill(n)?;
        if masked {
            for i in 0..payload.len() {
                payload[i] ^= mask[i % 4];
            }
        }
        match opcode {
            0x8 => Err("mesgd: connection closed".into()),
            0x9 => {
                self.write_frame(0xA, &payload)?;
                self.read_frame()
            }
            0xA => self.read_frame(),
            _ => Ok(payload),
        }
    }

    fn write_frame(&mut self, opcode: u8, payload: &[u8]) -> Result<(), Box<dyn Error>> {
        let n = payload.len();
        let mut frame = vec![0x80 | opcode];
        if n < 126 {
            frame.push(0x80 | n as u8);
        } else if n < 65536 {
            frame.push(0xFE);
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        } else {
            frame.push(0xFF);
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
        let mut mask = [0u8; 4];
        rand_bytes(&mut mask)?;
        frame.extend_from_slice(&mask);
        frame.extend(payload.iter().enumerate().map(|(i, b)| b ^ mask[i % 4]));
        self.stream.write_all(&frame)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::Cursor;
    use std::sync::{Arc, Mutex};

    fn conn() -> Conn {
        let pki = PKI::init("../fixtures/jwks.json").unwrap();
        let server_pub = pki.pub_jwk().unwrap();
        Conn {
            stream: Box::new(Cursor::new(Vec::new())),
            pki,
            server_pub: Some(server_pub),
            handlers: HashMap::new(),
            buf: Vec::new(),
        }
    }

    #[test]
    fn plain_frame() {
        let c = conn();
        let wire: Value = serde_json::from_str(
            &c.frame(json!({"to":"x/y","type":"ping","body":{"a":1}}), SendOpts::default()).unwrap(),
        )
        .unwrap();
        assert!(wire.get("body").is_some());
        assert!(wire.get("enc").is_none());
        assert!(wire.get("sig").is_none());
    }

    #[test]
    fn signed_sealed_roundtrip() {
        let mut c = conn();
        let wire_str = c
            .frame(
                json!({"to":"agents/alice/inbox","type":"task.request","body":{"cap":"summarize","n":3}}),
                SendOpts { sign: true, seal: true },
            )
            .unwrap();
        let wire: Value = serde_json::from_str(&wire_str).unwrap();
        assert!(wire.get("enc").is_some()); // sealed
        assert!(wire.get("body").is_none()); // body hidden
        assert_eq!(wire["to"], "agents/alice/inbox"); // routable cleartext
        assert!(wire.get("sig").is_some());

        let got = Arc::new(Mutex::new(None));
        let g = got.clone();
        c.on("task.request", move |m| *g.lock().unwrap() = Some(m));
        c.dispatch(wire_str.as_bytes()).unwrap();

        let m = got.lock().unwrap().clone().unwrap();
        assert_eq!(m["type"], "task.request");
        assert_eq!(m["body"]["cap"], "summarize"); // sealed body recovered
        let body = serde_json::to_string(&m["body"]).unwrap();
        assert!(PKI::check_with_pub(&c.pki.pub_jwk().unwrap(), &body, m["sig"].as_str().unwrap()).unwrap());
    }
}
