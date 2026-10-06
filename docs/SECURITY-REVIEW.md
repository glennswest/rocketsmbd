# Security review — 2026-10 (#39)

A self-review pass over rocketsmbd `main` (from 4c3b170), covering the scope of
#39: auth state machine, crypto usage, Kerberos/GSS, parsers, path/VFS, memory
safety, and resource exhaustion. It was done by reading the code adversarially
(three independent passes: auth/crypto, parsers/DoS/VFS, and every `unsafe`
block), with each finding checked against the code before it was listed.

**This is not an external review.** Nobody outside the project has looked at
the code yet; that remains open (see "Not done" below).

Severity: **Critical** = defeats a security control remotely; **High** =
remote authz bypass, remote crash/DoS, or memory exhaustion; **Medium** =
needs a position on the network path, a specific config, or local access;
**Low** = narrow impact or defence in depth.

Status: **fixed** (commit noted), **risk-accepted** (stated in SECURITY.md),
**open** (tracked issue).

## Findings

| ID | Sev | Finding | Status |
|----|-----|---------|--------|
| R1 | Critical | Encrypted sessions accepted plaintext requests and skipped signature checks on them. Once a channel was encrypting (`encrypt = true`, or after the client's first transform frame), `dispatch` skipped signature verification for every request on it, including ones that did not arrive in a transform. An on-path attacker could inject unsigned CREATE/READ/WRITE/SET_INFO with the victim's SessionId, and the replies went back signed but in cleartext. | open |
| R2 | High | An encrypted LOGOFF (normal cifs `seal` unmount) panicked the worker thread: the response re-encryption `unwrap`ped the channel LOGOFF had just removed. Each panic killed one worker (its share of new connections then hung in an unread accept queue), and the unwind freed connection buffers while io_uring ops still pointed into them. | open |
| R3 | High | A file handle was not tied to the tree it was opened on. SET_INFO took `read_only` and the rename root from the *request's* tree, so a user with share A read-only and share B writable could open `A\x` and delete it, rename it (or A's root) into B, or change its times, by sending SET_INFO with B's TreeId. Defeats #40 `read_only` / `read_only_users`. | open |
| R4 | High | Read-only trees allowed creation: CREATE with `FILE_OPEN_IF` and read-only access passed the read-only check, then created the file (`O_CREAT`) or directory (`mkdir`). | open |
| R5 | High | Sessions were never freed when their connection dropped (only LOGOFF removed them). Pre-auth: every NTLM NEGOTIATE token created a registry entry, so an unauthenticated client could grow memory without bound (≈40k sessions per compounded 4 MiB frame). Post-auth: open fds, OFD byte-range locks and pending delete-on-close outlived the connection, so locks stayed held until restart and fds could be exhausted. | open |
| R6 | High | A compound request's total response was unbounded: ~35k chained 1 MiB READs in one 4 MiB frame grow `tx` to tens of GiB (OOM), and a response over 16 MiB overflowed the 24-bit NBT length. | open |
| R7 | High | Pre-auth buffer pinning: a 4-byte NBT header declaring a 4 MiB frame grew the connection's rx buffer to 4 MiB (zero-filled, so committed), with no connection cap or handshake/idle timeout. | open |
| R8 | High | `encrypt = true` was silently ignored when no cipher was negotiated (SMB 2.x/3.0/3.0.2, or 3.1.1 without an encryption context): the session came up in cleartext. Combined with FSCTL_VALIDATE_NEGOTIATE_INFO never being checked against what the client sent, an on-path attacker could strip 3.1.1 from the dialect list to get an unencrypted session. | open |
| R9 | High | No MessageId window: a captured signed (or sealed) request could be replayed on the same connection and would execute again (re-delete, re-truncate, roll back a WRITE). | open |
| R10 | Medium | Session binding: an unauthenticated client could bind to any session ID (they were sequential), then LOGOFF it from the pending channel, destroying another user's session; binding to an established guest session needed no proof at all (hijack of its trees and handles). Binding was accepted with `multichannel = false` and below SMB 3.0. | open |
| R11 | Medium | Signing is optional by default and the client decides (`require_signing = false`; unsigned requests accepted unless the client set REQUIRED). With NTLM and no MIC/channel binding, that is the classic SMB relay/tamper setup. | open |
| R12 | Medium | Guest is allowed by default when no `[[user]]` exists — including Kerberos/AD-only configs — and `invalid_users` never matches a guest, so a deny-list-only share is open to guests. | open |
| R13 | Medium | CHANGE_NOTIFY completions on an encrypted session went out unsealed (and usually unsigned), leaking changed file names and allowing a forged completion. (Lease breaks avoid this only because leases aren't granted on encrypted sessions.) | open |
| R14 | Medium | No per-session/connection caps on open handles, trees, or pended CHANGE_NOTIFYs; one inotify instance per connection (default `max_user_instances` 128) lets 128 clients exhaust notify for everyone. | open |
| R15 | Medium | The packaged systemd unit runs as root, and paths are opened by plain joins (no `openat2(RESOLVE_BENEATH)`), so a symlink planted in a share by anyone with local write access reaches anything root can. | open |
| R16 | Low | Encrypted frames called `tx.clear()`, discarding responses (and deferred notify finals) already batched for the connection in the same pass — pipelined sealed clients lost responses. | open |
| R17 | Low | A second NEGOTIATE on a connection was accepted and reset dialect/cipher/preauth state under live sessions. | open |
| R18 | Low | The decrypted inner SessionId wasn't tied to the transform's SessionId; a sealed frame naming another (unencrypted) session on the same connection could take the zero-copy READ path, whose plan (and dup'd fd) was then dropped — an fd leak and no response. | open |
| R19 | Low | NTLMv2 proof compared with `!=` (not constant-time). Not exploitable (fresh challenge each attempt). | open |
| R20 | Low | A zero-length LOCK became a POSIX "to EOF" lock, blocking every later lock on the file. | open |
| R21 | Low | The share root itself could be deleted (CREATE `""` + delete-on-close on an empty share) or renamed. | open |
| R22 | Low | Opening a FIFO or device node in a share (or via a symlink) blocked the worker thread in `open`. | open |
| R23 | Low | Health endpoint: the 2 s timeout was per read, so a client trickling bytes could hold the single-threaded endpoint for hours. | open |
| R24 | Low | Lease table: handle-caching leases outlive CLOSE (grows until disconnect); a client reusing another's lease key overwrites its grant; the key ignores `st_dev`. | open |
| R25 | Low | Handle paths go stale when another handle renames a parent; `exists()` then `rename()` races a non-replacing rename. | open |
| R26 | Low | Directory snapshots stat every entry per handle; many handles on a huge directory multiply memory. | open |
| R27 | Low | CANCEL is exempt from signature checks, so an on-path attacker can cancel pended notifies. | open |
| U1 | High | `unsafe` audit: `KRB5_KTNAME` was `setenv`'d on worker threads while other workers' GSS calls `getenv` — a glibc use-after-free race. | fixed (b5c2ff8) |
| U2 | High | `unsafe` audit: a worker exiting on error/panic dropped connection buffers before its ring, with ops armed into them. | fixed (b5c2ff8) |
| U3 | Low | `unsafe` audit: `fstat_meta(-1)` was UB; GSS buffers read without null checks; an empty GSS buffer set leaked; the queued zero-copy READ's dup fd leaked on drop; a server-closed connection with a recv armed lingered; 24-bit slot index unchecked. | fixed (b5c2ff8) |

### Info (interop with security relevance)

- Multichannel + encryption: binding derives per-channel encryption keys from
  the binding preauth hash; MS-SMB2 uses session-wide keys, so a compliant
  client's sealed traffic on a second channel fails to decrypt (the server
  disconnects — fails closed). Fixing it needs a session-wide nonce counter.
- Kerberos + AES-256 ciphers: the KDF takes the 16-byte truncated session key;
  MS-SMB2 wants the full key for AES-256, so Kerberos + AES-256 won't
  interoperate (fails closed).
- An unknown NTLM user maps to guest when guest is allowed ("bad user" map to
  guest). Deliberate; documented.

## Checked and found sound

- **Signing**: the signature field is zeroed, the exact compound element is
  MAC'd, and the compare is constant-time; every response on a keyed session is
  signed in the post-pass, including errors and the final SESSION_SETUP.
- **Cross-connection isolation**: requests need an established channel on
  *this* connection; tree and file IDs are per session and generation-tagged;
  related compound elements resolve against the effective session's own tables.
- **NTLM**: NTLMv1/LM refused; a known user with a wrong password is refused,
  not mapped to guest; challenges are 8 random bytes, single-use; KEY_EXCH RC4
  unwrap correct.
- **3.1.1 preauth** chaining and **KDF** labels/contexts per MS-SMB2;
  **AEAD** AAD, nonce lengths, OriginalMessageSize check, disconnect on failure;
  outbound nonce is a strictly increasing per-channel counter under a
  per-channel key — no nonce reuse.
- **Kerberos**: replay cache and clock-skew checks left on; PAC used only when
  GSS reports it authenticated; PAC parser bounds every count and offset;
  multi-leg rejected; the hand-declared `gssapi_ext` FFI matches MIT/Heimdal
  headers; every GSS object is released on every path.
- **Parsers**: every body field is read through bounds-checked `get`; SPNEGO
  DER is non-recursive with bounded lengths; NBT framing caps the frame size;
  compound chaining always terminates. Now fuzzed: `process_frame`, NTLMSSP,
  SPNEGO, TRANSFORM (see below).
- **Paths**: `..` and NUL rejected, both separators handled; `:` streams and
  drive letters become literal names (no escape).
- **io_uring lifetimes**: buffers referenced by in-flight SQEs are not resized
  or freed until their CQE; teardown waits for `inflight == 0` (the phase-2
  disconnect-during-notify fix still holds). Every `unsafe` block now carries a
  `// SAFETY:` comment stating its invariant.

## Fuzzing

Targets (`fuzz/fuzz_targets/`): `process_frame`, `ntlm`, `spnego`,
`transform`. Their bodies live in `rocketsmbd::fuzzing`, so `cargo test`
compiles them and runs each over a small built-in corpus — the targets can't
silently stop compiling again (#50, #51).

## Not done

- **External review.** Still needed before the "don't expose 445 to the
  internet" caveat can go.
