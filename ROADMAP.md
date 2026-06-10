# rocketsmbd Roadmap

Tracking the path from a fast LAN file server to a hardened, distro-packaged
1.0. Items link to GitHub issues. Dates are targets, not promises.

## Shipped

- **0.1** — io_uring reactor, zero-copy splice reads, SMB 2.0.2–3.0.2, guest
  read/write. ~4× Samba on reads.
- **0.2** — NTLMv2 auth + user DB, SMB2/3 signing, SMB 3.1.1 preauth
  integrity, SPNEGO, IPC$ stub, byte-range locks, CHANGE_NOTIFY.
- **0.3** — SMB3 **multichannel** (shared session registry, channel binding,
  per-channel signing), server-side read-ahead, lock-free read I/O. Single
  mount 169 Gbps loopback / ~47 Gbps cross-VM jumbo.

## 0.4 — throughput & packaging

- Linked io_uring chain for full zero-copy reads (done; cuts CPU/read).
- `advertise_only` for multichannel NIC selection (done).
- Distro packaging: `.deb` + `.rpm` artifacts, systemd unit, man page, CI.
- Fedora COPR + Debian repo for early users (#22, #23).
- Fuzz the SMB2 + NTLMSSP parsers — cargo-fuzz (#20).

## 0.5 — efficiency & robustness

- SQPOLL (#13), registered files + buffers (#14), send_zc (#15).
- Multishot accept/recv (#16), worker core pinning to NIC RSS (#17).
- Intra-connection read concurrency (#12).
- Oplocks/leases with caching (#18).

## 0.6 — security & SMB3 completeness

- SMB3 encryption, AES-128/256-GCM (#10).
- Zero-copy path for signed/encrypted reads (#11).
- Windows Server interop + head-to-head benchmark (#21).

## 1.0 — stable

- Security review complete, fuzzing in CI, signing-required option,
  encryption available, docs + config stable (#24).
- Official Fedora (Rust SIG) and Debian (debcargo) packages.

## Beyond

- SMB Direct (RDMA) transport for 400/800GbE (#19).
