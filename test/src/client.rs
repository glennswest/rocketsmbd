//! A small blocking SMB2/3 client for the test container: just enough of the
//! protocol to drive rocketsmbd through its main paths. The crypto (NTLMv2,
//! SP800-108 key derivation, signing, AEAD transform) is rocketsmbd's own
//! library code, used here from the client's side of the wire.

use rocketsmbd::crypto;
use rocketsmbd::ntlm;
use rocketsmbd::smb2::{self, EncCtx, SignCtx};
use rocketsmbd::status;
use rocketsmbd::wire::{from_utf16le, utf16le, Put, Rdr};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

pub type R<T> = Result<T, String>;

const SEC_SIGNING_ENABLED: u16 = 0x1;
const SEC_SIGNING_REQUIRED: u16 = 0x2;

/// One response (or unsolicited notification) message, header included.
pub struct Resp {
    pub status: u32,
    pub cmd: u16,
    pub flags: u32,
    pub msg_id: u64,
    pub tree: u32,
    pub sess: u64,
    pub raw: Vec<u8>,
}

impl Resp {
    pub fn body(&self) -> &[u8] {
        &self.raw[64..]
    }
    fn parse(raw: Vec<u8>) -> R<Resp> {
        if raw.len() < 64 || raw[..4] != [0xFE, b'S', b'M', b'B'] {
            return Err(format!("not an SMB2 message ({} bytes)", raw.len()));
        }
        let u32a = |o: usize| u32::from_le_bytes(raw[o..o + 4].try_into().unwrap());
        let flags = u32a(16);
        Ok(Resp {
            status: u32a(8),
            cmd: u16::from_le_bytes(raw[12..14].try_into().unwrap()),
            flags,
            msg_id: u64::from_le_bytes(raw[24..32].try_into().unwrap()),
            tree: if flags & smb2::FLAG_ASYNC != 0 { 0 } else { u32a(36) },
            sess: u64::from_le_bytes(raw[40..48].try_into().unwrap()),
            raw,
        })
    }
}

/// What CREATE returned.
pub struct Opened {
    pub status: u32,
    pub fid: u64,
    /// OplockLevel byte (0xFF = a lease was granted).
    pub oplock: u8,
    /// Granted lease state from the RqLs response context (0 = none).
    pub lease_state: u32,
}

pub struct Client {
    s: TcpStream,
    next_id: u64,
    pub dialect: u16,
    pub max_read: u32,
    pub sess: u64,
    pub guest: bool,
    sign: Option<SignCtx>,
    sign_requests: bool,
    tx_enc: Option<EncCtx>,
    rx_enc: Option<EncCtx>,
    /// Seal outgoing requests (requires a negotiated cipher).
    pub seal: bool,
    preauth: [u8; 64],
    cipher: u16,
    /// Unsolicited messages (lease breaks) received while waiting for a reply.
    pub unsolicited: Vec<Resp>,
    /// The last request exactly as written to the socket (NBT included).
    pub last_wire: Vec<u8>,
}

impl Client {
    pub fn connect(addr: &str) -> R<Client> {
        let s = TcpStream::connect(addr).map_err(|e| format!("connect {addr}: {e}"))?;
        s.set_nodelay(true).ok();
        s.set_read_timeout(Some(Duration::from_secs(30))).ok();
        Ok(Client {
            s,
            next_id: 0,
            dialect: 0,
            max_read: 65536,
            sess: 0,
            guest: false,
            sign: None,
            sign_requests: false,
            tx_enc: None,
            rx_enc: None,
            seal: false,
            preauth: [0; 64],
            cipher: 0,
            unsolicited: Vec::new(),
            last_wire: Vec::new(),
        })
    }

    pub fn cipher(&self) -> u16 {
        self.cipher
    }

    fn hdr(&mut self, cmd: u16, tree: u32, charge: u16) -> (Vec<u8>, u64) {
        let id = self.next_id;
        self.next_id += charge.max(1) as u64;
        let mut v = Vec::with_capacity(128);
        v.pbytes(&[0xFE, b'S', b'M', b'B']);
        v.p16(64);
        v.p16(charge);
        v.p32(0);
        v.p16(cmd);
        v.p16(256); // credits requested
        v.p32(0); // flags
        v.p32(0); // next
        v.p64(id);
        v.p32(0); // pid
        v.p32(tree);
        v.p64(self.sess);
        v.zeros(16);
        (v, id)
    }

    /// Write one message: sealed, signed, or plain.
    fn send_msg(&mut self, mut msg: Vec<u8>) -> R<()> {
        let mut wire = Vec::with_capacity(msg.len() + 60);
        if self.seal {
            let enc = self.tx_enc.as_mut().ok_or("seal without encryption keys")?;
            smb2::wrap_transform(&msg, enc, self.sess, &mut wire);
        } else {
            if self.sign_requests {
                if let Some(sc) = &self.sign {
                    let n = msg.len();
                    smb2::sign_in_place(&mut msg, 0, n, sc);
                }
            }
            let n = msg.len() as u32;
            wire.extend_from_slice(&[0, (n >> 16) as u8, (n >> 8) as u8, n as u8]);
            wire.extend_from_slice(&msg);
        }
        self.s.write_all(&wire).map_err(|e| format!("send: {e}"))?;
        self.last_wire = wire;
        Ok(())
    }

    /// Write raw bytes as they are (a replay).
    pub fn send_wire(&mut self, wire: &[u8]) -> R<()> {
        self.s.write_all(wire).map_err(|e| format!("send: {e}"))
    }

    /// Read one frame; decrypt a transform; check the signature of a signed
    /// plaintext reply. `Ok(None)` = the server closed the connection.
    pub fn recv(&mut self) -> R<Option<Resp>> {
        let mut nbt = [0u8; 4];
        match self.s.read_exact(&mut nbt) {
            Ok(()) => {}
            Err(e) if matches!(e.kind(), std::io::ErrorKind::UnexpectedEof | std::io::ErrorKind::ConnectionReset) => {
                return Ok(None)
            }
            Err(e) => return Err(format!("recv: {e}")),
        }
        let len = ((nbt[1] as usize) << 16) | ((nbt[2] as usize) << 8) | nbt[3] as usize;
        let mut frame = vec![0u8; len];
        self.s.read_exact(&mut frame).map_err(|e| format!("recv body: {e}"))?;
        if smb2::is_transform(&frame) {
            let enc = self.rx_enc.as_ref().ok_or("sealed reply without keys")?;
            let plain = smb2::decrypt_transform(&frame, enc).ok_or("sealed reply failed to decrypt")?;
            return Resp::parse(plain).map(Some);
        }
        let r = Resp::parse(frame)?;
        if let Some(sc) = &self.sign {
            let signed = r.flags & smb2::FLAG_SIGNED != 0;
            if signed && !smb2::verify_signature(&r.raw, sc) {
                return Err(format!("bad signature on reply to command {}", r.cmd));
            }
            if !signed && self.sign_requests && r.msg_id != u64::MAX && r.status != status::PENDING {
                return Err(format!("unsigned reply to command {} on a signed session", r.cmd));
            }
        }
        Ok(Some(r))
    }

    /// Send a request and wait for its final reply (interim PENDING replies
    /// and unsolicited notifications are set aside).
    pub fn request(&mut self, cmd: u16, tree: u32, body: &[u8], charge: u16) -> R<Resp> {
        let (mut msg, id) = self.hdr(cmd, tree, charge);
        msg.extend_from_slice(body);
        self.send_msg(msg)?;
        self.wait_for(id)
    }

    fn wait_for(&mut self, id: u64) -> R<Resp> {
        loop {
            let r = self.recv()?.ok_or("connection closed by server")?;
            if r.msg_id == id {
                if r.status == status::PENDING && r.flags & smb2::FLAG_ASYNC != 0 {
                    continue;
                }
                return Ok(r);
            }
            self.unsolicited.push(r);
        }
    }

    /// Wait up to `timeout` for an unsolicited message of command `cmd`.
    pub fn wait_unsolicited(&mut self, cmd: u16, timeout: Duration) -> R<Option<Resp>> {
        if let Some(i) = self.unsolicited.iter().position(|r| r.cmd == cmd) {
            return Ok(Some(self.unsolicited.remove(i)));
        }
        self.s.set_read_timeout(Some(timeout)).ok();
        let got = match self.recv() {
            Ok(Some(r)) if r.cmd == cmd => Some(r),
            Ok(Some(r)) => {
                self.unsolicited.push(r);
                None
            }
            Ok(None) => None,
            Err(e) if e.contains("timed out") || e.contains("WouldBlock") || e.contains("Resource temporarily") => None,
            Err(e) => {
                self.s.set_read_timeout(Some(Duration::from_secs(30))).ok();
                return Err(e);
            }
        };
        self.s.set_read_timeout(Some(Duration::from_secs(30))).ok();
        Ok(got)
    }

    /// True if the server closes the connection within `timeout`.
    pub fn closed_within(&mut self, timeout: Duration) -> bool {
        self.s.set_read_timeout(Some(timeout)).ok();
        let mut b = [0u8; 4096];
        let closed = loop {
            match self.s.read(&mut b) {
                Ok(0) => break true,
                Ok(_) => continue, // a reply to something else; keep reading
                Err(e) => break e.kind() == std::io::ErrorKind::ConnectionReset,
            }
        };
        self.s.set_read_timeout(Some(Duration::from_secs(30))).ok();
        closed
    }

    // ------------------------------------------------------------ NEGOTIATE

    /// NEGOTIATE offering `dialects`; for 3.1.1 also a SHA-512 preauth context
    /// and, with `cipher`, an encryption context offering just that cipher.
    pub fn negotiate(&mut self, dialects: &[u16], cipher: Option<u16>, require_signing: bool) -> R<()> {
        let (mut m, id) = self.hdr(smb2::CMD_NEGOTIATE, 0, 0);
        let secmode = SEC_SIGNING_ENABLED | if require_signing { SEC_SIGNING_REQUIRED } else { 0 };
        let has311 = dialects.contains(&0x0311);
        m.p16(36);
        m.p16(dialects.len() as u16);
        m.p16(secmode);
        m.p16(0);
        m.p32(0x2 | 0x4 | 0x40); // leasing, large MTU, encryption
        let mut guid = [0u8; 16];
        rocketsmbd::config::urandom(&mut guid);
        m.pbytes(&guid);
        let ctx_off_pos = m.len();
        m.p32(0);
        m.p16(0);
        m.p16(0);
        for d in dialects {
            m.p16(*d);
        }
        if has311 {
            let mut n = 0u16;
            while m.len() % 8 != 0 {
                m.p8(0);
            }
            let ctx_off = m.len();
            // PREAUTH_INTEGRITY_CAPABILITIES: SHA-512, 32-byte salt.
            m.p16(1);
            m.p16(38);
            m.p32(0);
            m.p16(1);
            m.p16(32);
            m.p16(1);
            let mut salt = [0u8; 32];
            rocketsmbd::config::urandom(&mut salt);
            m.pbytes(&salt);
            n += 1;
            if let Some(c) = cipher {
                while m.len() % 8 != 0 {
                    m.p8(0);
                }
                m.p16(2); // ENCRYPTION_CAPABILITIES
                m.p16(4);
                m.p32(0);
                m.p16(1);
                m.p16(c);
                n += 1;
            }
            m[ctx_off_pos..ctx_off_pos + 4].copy_from_slice(&(ctx_off as u32).to_le_bytes());
            m[ctx_off_pos + 4..ctx_off_pos + 6].copy_from_slice(&n.to_le_bytes());
        }
        let req = m.clone();
        self.send_msg(m)?;
        let r = self.wait_for(id)?;
        if r.status != status::SUCCESS {
            return Err(format!("NEGOTIATE status {:#x}", r.status));
        }
        let b = r.body();
        let u16b = |o: usize| u16::from_le_bytes(b[o..o + 2].try_into().unwrap());
        let u32b = |o: usize| u32::from_le_bytes(b[o..o + 4].try_into().unwrap());
        self.dialect = u16b(4);
        self.max_read = u32b(32).min(1 << 20);
        self.cipher = 0;
        if self.dialect == 0x0311 {
            let h0 = crypto::sha512(&[&[0u8; 64], &req]);
            self.preauth = crypto::sha512(&[&h0, &r.raw]);
            // The cipher the server picked, from its negotiate contexts.
            let (count, mut off) = (u16b(6) as usize, u32b(60) as usize);
            for _ in 0..count {
                let Some(h) = r.raw.get(off..off + 8) else { break };
                let (t, l) = (u16::from_le_bytes([h[0], h[1]]), u16::from_le_bytes([h[2], h[3]]) as usize);
                if t == 2 && l >= 4 {
                    self.cipher = u16::from_le_bytes([r.raw[off + 10], r.raw[off + 11]]);
                }
                off = (off + 8 + l + 7) & !7;
            }
        }
        Ok(())
    }

    // -------------------------------------------------------- SESSION_SETUP

    fn ss_body(&self, blob: &[u8], secmode: u16) -> Vec<u8> {
        let mut b = Vec::new();
        b.p16(25);
        b.p8(0);
        b.p8(secmode as u8);
        b.p32(0);
        b.p32(0);
        b.p16(88);
        b.p16(blob.len() as u16);
        b.p64(0);
        b.pbytes(blob);
        b
    }

    /// NTLM session setup: `Some((user, password))` for NTLMv2, `None` for an
    /// anonymous (guest) session. Returns the final status; on success the
    /// session's signing (and, with a cipher, encryption) keys are set.
    pub fn session_setup(&mut self, cred: Option<(&str, &str)>, require_signing: bool) -> R<u32> {
        let secmode = SEC_SIGNING_ENABLED | if require_signing { SEC_SIGNING_REQUIRED } else { 0 };
        // Type 1.
        let mut t1 = ntlm::SIG.to_vec();
        t1.p32(1);
        t1.p32(0x0008_8207); // NEGOTIATE_UNICODE|NTLM|ALWAYS_SIGN|EXTENDED_SESSIONSECURITY|...
        t1.zeros(16);
        let body = self.ss_body(&t1, secmode);
        let (mut m, id) = self.hdr(smb2::CMD_SESSION_SETUP, 0, 1);
        m.extend_from_slice(&body);
        let req1 = m.clone();
        self.send_msg(m)?;
        let r1 = self.wait_for(id)?;
        if r1.status != status::MORE_PROCESSING_REQUIRED {
            return Ok(r1.status);
        }
        self.sess = r1.sess;
        if self.dialect == 0x0311 {
            self.preauth = crypto::sha512(&[&self.preauth, &req1]);
            self.preauth = crypto::sha512(&[&self.preauth, &r1.raw]);
        }
        let tok = r1
            .raw
            .windows(8)
            .position(|w| w == ntlm::SIG)
            .ok_or("no NTLMSSP challenge in the reply")?;
        let chal: [u8; 8] = r1.raw.get(tok + 24..tok + 32).ok_or("short challenge")?.try_into().unwrap();

        // Type 3.
        let mut key = None;
        let t3 = match cred {
            None => {
                let mut t = ntlm::SIG.to_vec();
                t.p32(3);
                t
            }
            Some((user, pass)) => {
                let nt = crypto::nt_hash(pass);
                let mut idb = utf16le(&user.to_uppercase());
                idb.extend_from_slice(&utf16le(""));
                let v2 = crypto::hmac_md5(&nt, &idb);
                let mut cc = [0u8; 8];
                rocketsmbd::config::urandom(&mut cc);
                let mut temp = vec![1u8, 1, 0, 0, 0, 0, 0, 0];
                temp.extend_from_slice(&[0; 8]); // timestamp
                temp.extend_from_slice(&cc);
                temp.extend_from_slice(&[0; 8]);
                let mut pb = chal.to_vec();
                pb.extend_from_slice(&temp);
                let proof = crypto::hmac_md5(&v2, &pb);
                let mut nt_resp = proof.to_vec();
                nt_resp.extend_from_slice(&temp);
                key = Some(crypto::hmac_md5(&v2, &proof));
                let user16 = utf16le(user);
                let mut t = ntlm::SIG.to_vec();
                t.p32(3);
                let mut off = 64usize;
                for len in [0usize, nt_resp.len(), 0, user16.len(), 0, 0] {
                    t.p16(len as u16);
                    t.p16(len as u16);
                    t.p32(off as u32);
                    off += len;
                }
                t.p32(0); // no KEY_EXCH: session key = session base key
                t.pbytes(&nt_resp);
                t.pbytes(&user16);
                t
            }
        };
        let body = self.ss_body(&t3, secmode);
        let (mut m, id) = self.hdr(smb2::CMD_SESSION_SETUP, 0, 1);
        m.extend_from_slice(&body);
        if self.dialect == 0x0311 {
            self.preauth = crypto::sha512(&[&self.preauth, &m]);
        }
        if let Some(k) = key {
            // The final reply is signed with the new key: set it before reading.
            self.sign = Some(smb2::derive_sign_ctx(self.dialect, &k, &self.preauth));
        }
        self.send_msg(m)?;
        let r = self.wait_for(id)?;
        if r.status != status::SUCCESS {
            self.sign = None;
            return Ok(r.status);
        }
        self.guest = u16::from_le_bytes(r.body()[2..4].try_into().unwrap()) & 1 != 0;
        if let Some(k) = key {
            if r.flags & smb2::FLAG_SIGNED == 0 {
                return Err("final SESSION_SETUP reply is not signed".into());
            }
            self.sign_requests = require_signing;
            if self.cipher != 0 && self.dialect == 0x0311 {
                let (c2s, s2c) = crypto::smb311_encryption_keys(self.cipher, &k, &self.preauth);
                // wrap_transform seals with `s2c` and decrypt_transform opens
                // with `c2s`: the client's view swaps them.
                self.tx_enc = Some(EncCtx { cipher: self.cipher, c2s: [0; 32], s2c: c2s, nonce_ctr: 0 });
                self.rx_enc = Some(EncCtx { cipher: self.cipher, c2s: s2c, s2c: [0; 32], nonce_ctr: 0 });
            }
        }
        Ok(r.status)
    }

    // -------------------------------------------------------------- TREE/IO

    pub fn tree_connect(&mut self, share: &str) -> R<(u32, u32)> {
        let path = utf16le(&format!("\\\\127.0.0.1\\{share}"));
        let mut b = Vec::new();
        b.p16(9);
        b.p16(0);
        b.p16(72);
        b.p16(path.len() as u16);
        b.pbytes(&path);
        let r = self.request(smb2::CMD_TREE_CONNECT, 0, &b, 1)?;
        Ok((r.status, r.tree))
    }

    /// CREATE. `lease`: request an R|H lease under this key.
    pub fn create(&mut self, tree: u32, name: &str, disposition: u32, desired: u32, options: u32, lease: Option<[u8; 16]>) -> R<Opened> {
        let n = utf16le(name);
        let mut ctx: Vec<u8> = Vec::new();
        if let Some(k) = lease {
            let mut data = k.to_vec();
            data.p32(smb2::LEASE_READ_CACHING | smb2::LEASE_HANDLE_CACHING);
            data.zeros(12);
            ctx.p32(0);
            ctx.p16(16);
            ctx.p16(4);
            ctx.p16(0);
            ctx.p16(24);
            ctx.p32(data.len() as u32);
            ctx.pbytes(smb2::CTX_NAME_RQLS);
            ctx.zeros(4);
            ctx.pbytes(&data);
        }
        let ctx_off = if ctx.is_empty() { 0 } else { (120 + n.len()).div_ceil(8) * 8 };
        let mut b = Vec::new();
        b.p16(57);
        b.p8(0);
        b.p8(if lease.is_some() { smb2::OPLOCK_LEASE } else { 0 });
        b.p32(2); // impersonation
        b.p64(0);
        b.p64(0);
        b.p32(desired);
        b.p32(0); // attributes
        b.p32(7); // share all
        b.p32(disposition);
        b.p32(options);
        b.p16(120);
        b.p16(n.len() as u16);
        b.p32(ctx_off as u32);
        b.p32(ctx.len() as u32);
        b.pbytes(&n);
        if !ctx.is_empty() {
            while 64 + b.len() < ctx_off {
                b.p8(0);
            }
            b.pbytes(&ctx);
        }
        if b.len() == 56 {
            b.p8(0); // empty name: the body still carries one byte
        }
        let r = self.request(smb2::CMD_CREATE, tree, &b, 1)?;
        if r.status != status::SUCCESS {
            return Ok(Opened { status: r.status, fid: 0, oplock: 0, lease_state: 0 });
        }
        let body = r.body();
        let fid = u64::from_le_bytes(body[72..80].try_into().unwrap());
        let mut lease_state = 0;
        let (coff, clen) = (
            u32::from_le_bytes(body[80..84].try_into().unwrap()) as usize,
            u32::from_le_bytes(body[84..88].try_into().unwrap()) as usize,
        );
        if clen > 0 {
            // First context's data: LeaseKey (16) then LeaseState.
            if let Some(c) = r.raw.get(coff..coff + clen) {
                let doff = u16::from_le_bytes([c[10], c[11]]) as usize;
                if let Some(s) = c.get(doff + 16..doff + 20) {
                    lease_state = u32::from_le_bytes(s.try_into().unwrap());
                }
            }
        }
        Ok(Opened { status: r.status, fid, oplock: body[2], lease_state })
    }

    fn fid(b: &mut Vec<u8>, fid: u64) {
        b.p64(fid);
        b.p64(fid);
    }

    pub fn write(&mut self, tree: u32, fid: u64, off: u64, data: &[u8]) -> R<u32> {
        let mut b = Vec::with_capacity(48 + data.len());
        b.p16(49);
        b.p16(64 + 48);
        b.p32(data.len() as u32);
        b.p64(off);
        Self::fid(&mut b, fid);
        b.p32(0);
        b.p32(0);
        b.p16(0);
        b.p16(0);
        b.p32(0);
        b.pbytes(data);
        let charge = data.len().div_ceil(65536).max(1) as u16;
        Ok(self.request(smb2::CMD_WRITE, tree, &b, charge)?.status)
    }

    pub fn read(&mut self, tree: u32, fid: u64, off: u64, len: u32) -> R<(u32, Vec<u8>)> {
        let mut b = Vec::new();
        b.p16(49);
        b.p8(0x50);
        b.p8(0);
        b.p32(len);
        b.p64(off);
        Self::fid(&mut b, fid);
        b.p32(0);
        b.p32(0);
        b.p32(0);
        b.p16(0);
        b.p16(0);
        b.p8(0);
        let charge = (len as usize).div_ceil(65536).max(1) as u16;
        let r = self.request(smb2::CMD_READ, tree, &b, charge)?;
        if r.status != status::SUCCESS {
            return Ok((r.status, Vec::new()));
        }
        let body = r.body();
        let doff = body[2] as usize;
        let dlen = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
        let data = r.raw.get(doff..doff + dlen).ok_or("READ reply data out of range")?.to_vec();
        Ok((r.status, data))
    }

    /// Write `data` at 0 in `max_read`-sized chunks.
    pub fn write_all(&mut self, tree: u32, fid: u64, data: &[u8]) -> R<()> {
        let chunk = self.max_read as usize;
        for (i, c) in data.chunks(chunk).enumerate() {
            let st = self.write(tree, fid, (i * chunk) as u64, c)?;
            if st != status::SUCCESS {
                return Err(format!("WRITE at {} status {st:#x}", i * chunk));
            }
        }
        Ok(())
    }

    /// Read `len` bytes from 0 in `max_read`-sized chunks.
    pub fn read_all(&mut self, tree: u32, fid: u64, len: usize) -> R<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let n = (len - out.len()).min(self.max_read as usize) as u32;
            let (st, d) = self.read(tree, fid, out.len() as u64, n)?;
            if st != status::SUCCESS {
                return Err(format!("READ at {} status {st:#x}", out.len()));
            }
            if d.is_empty() {
                return Err(format!("READ at {} returned nothing", out.len()));
            }
            out.extend_from_slice(&d);
        }
        Ok(out)
    }

    pub fn close(&mut self, tree: u32, fid: u64) -> R<u32> {
        let mut b = Vec::new();
        b.p16(24);
        b.p16(0);
        b.p32(0);
        Self::fid(&mut b, fid);
        Ok(self.request(smb2::CMD_CLOSE, tree, &b, 1)?.status)
    }

    /// QUERY_DIRECTORY (FileIdBothDirectoryInformation, "*") until
    /// NO_MORE_FILES: the entry names.
    pub fn list(&mut self, tree: u32, fid: u64) -> R<Vec<String>> {
        let pat = utf16le("*");
        let mut names = Vec::new();
        for i in 0.. {
            let mut b = Vec::new();
            b.p16(33);
            b.p8(0x25);
            b.p8(if i == 0 { 1 } else { 0 }); // RESTART_SCANS first
            b.p32(0);
            Self::fid(&mut b, fid);
            b.p16(96);
            b.p16(pat.len() as u16);
            b.p32(65536);
            b.pbytes(&pat);
            let r = self.request(smb2::CMD_QUERY_DIRECTORY, tree, &b, 1)?;
            if r.status == status::NO_MORE_FILES {
                break;
            }
            if r.status != status::SUCCESS {
                return Err(format!("QUERY_DIRECTORY status {:#x}", r.status));
            }
            let body = r.body();
            let off = u16::from_le_bytes([body[2], body[3]]) as usize;
            let len = u32::from_le_bytes(body[4..8].try_into().unwrap()) as usize;
            let buf = r.raw.get(off..off + len).ok_or("QUERY_DIRECTORY data out of range")?;
            let mut p = 0usize;
            loop {
                let mut rd = Rdr::new(buf.get(p..).ok_or("bad entry offset")?);
                let next = rd.u32().ok_or("short entry")? as usize;
                let nlen = u32::from_le_bytes(buf.get(p + 60..p + 64).ok_or("short entry")?.try_into().unwrap()) as usize;
                let name = buf.get(p + 104..p + 104 + nlen).ok_or("short entry name")?;
                names.push(from_utf16le(name));
                if next == 0 {
                    break;
                }
                p += next;
            }
            if i > 10_000 {
                return Err("QUERY_DIRECTORY never ended".into());
            }
        }
        Ok(names)
    }

    pub fn echo(&mut self) -> R<u32> {
        let mut b = Vec::new();
        b.p16(4);
        b.p16(0);
        Ok(self.request(smb2::CMD_ECHO, 0, &b, 1)?.status)
    }

    pub fn logoff(&mut self) -> R<u32> {
        let mut b = Vec::new();
        b.p16(4);
        b.p16(0);
        Ok(self.request(smb2::CMD_LOGOFF, 0, &b, 1)?.status)
    }

    /// Send a request in plaintext, unsigned, even on a sealed session.
    pub fn plain_request(&mut self, cmd: u16, tree: u32, body: &[u8]) -> R<Resp> {
        let (seal, sign) = (self.seal, self.sign_requests);
        self.seal = false;
        self.sign_requests = false;
        let r = self.request(cmd, tree, body, 1);
        self.seal = seal;
        self.sign_requests = sign;
        r
    }
}
