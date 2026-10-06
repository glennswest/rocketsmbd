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
| R1 | Critical | Encrypted sessions accepted plaintext requests and skipped signature checks on them. Once a channel was encrypting (`encrypt = true`, or after the client's first transform frame), `dispatch` skipped signature verification for every request on it, including ones that did not arrive in a transform. An on-path attacker could inject unsigned CREATE/READ/WRITE/SET_INFO with the victim's SessionId, and the replies went back signed but in cleartext. | fixed (a1686f8) |
| R2 | High | An encrypted LOGOFF (normal cifs `seal` unmount) panicked the worker thread: the response re-encryption `unwrap`ped the channel LOGOFF had just removed. Each panic killed one worker (its share of new connections then hung in an unread accept queue), and the unwind freed connection buffers while io_uring ops still pointed into them. | fixed (a1686f8) |
| R3 | High | A file handle was not tied to the tree it was opened on. SET_INFO took `read_only` and the rename root from the *request's* tree, so a user with share A read-only and share B writable could open `A\x` and delete it, rename it (or A's root) into B, or change its times, by sending SET_INFO with B's TreeId. Defeats #40 `read_only` / `read_only_users`. | fixed (a1686f8); TREE_DISCONNECT also closes the tree's opens |
| R4 | High | Read-only trees allowed creation: CREATE with `FILE_OPEN_IF` and read-only access passed the read-only check, then created the file (`O_CREAT`) or directory (`mkdir`). | fixed (a1686f8); DELETE/WRITE_ATTRIBUTES/WRITE_EA/WRITE_DAC/WRITE_OWNER also refused on read-only trees |
| R5 | High | Sessions were never freed when their connection dropped (only LOGOFF removed them). Pre-auth: every NTLM NEGOTIATE token created a registry entry, so an unauthenticated client could grow memory without bound (≈40k sessions per compounded 4 MiB frame). Post-auth: open fds, OFD byte-range locks and pending delete-on-close outlived the connection, so locks stayed held until restart and fds could be exhausted. | fixed (a1686f8): sessions end with their last connection; ≤ 4 half-open setups per connection |
| R6 | High | A compound request's total response was unbounded: ~35k chained 1 MiB READs in one 4 MiB frame grow `tx` to tens of GiB (OOM), and a response over 16 MiB overflowed the 24-bit NBT length. | fixed (a1686f8): ≤ 128 members and ~8 MiB of responses per frame, else disconnect |
| R7 | High | Pre-auth buffer pinning: a 4-byte NBT header declaring a 4 MiB frame grew the connection's rx buffer to 4 MiB (zero-filled, so committed), with no connection cap or handshake/idle timeout. | partly fixed (a1686f8): 128 KiB frame cap before a session is established. Connection caps and timeouts: #55 |
| R8 | High | `encrypt = true` was silently ignored when no cipher was negotiated (SMB 2.x/3.0/3.0.2, or 3.1.1 without an encryption context): the session came up in cleartext. Combined with FSCTL_VALIDATE_NEGOTIATE_INFO never being checked against what the client sent, an on-path attacker could strip 3.1.1 from the dialect list to get an unencrypted session. | fixed (a1686f8): `encrypt = true` refuses sessions that can't be sealed; VALIDATE_NEGOTIATE_INFO checked, mismatch disconnects |
| R9 | High | No MessageId window: a captured signed (or sealed) request could be replayed on the same connection and would execute again (re-delete, re-truncate, roll back a WRITE). | fixed (a1686f8): per-connection MessageId window, reuse disconnects |
| R10 | Medium | Session binding: an unauthenticated client could bind to any session ID (they were sequential), then LOGOFF it from the pending channel, destroying another user's session; binding to an established guest session needed no proof at all (hijack of its trees and handles). Binding was accepted with `multichannel = false` and below SMB 3.0. | fixed (a1686f8): random session ids; binding needs `multichannel`, SMB 3.x and an established non-guest session; LOGOFF needs an established channel |
| R11 | Medium | Signing is optional by default and the client decides (`require_signing = false`; unsigned requests accepted unless the client set REQUIRED). With NTLM and no MIC/channel binding, that is the classic SMB relay/tamper setup. | risk-accepted for now (SECURITY.md: set `require_signing = true`); default change is the owner's call |
| R12 | Medium | Guest is allowed by default when no `[[user]]` exists — including Kerberos/AD-only configs — and `invalid_users` never matches a guest, so a deny-list-only share is open to guests. | risk-accepted for now (SECURITY.md: set `allow_guest = false` explicitly); default change is the owner's call |
| R13 | Medium | CHANGE_NOTIFY completions on an encrypted session went out unsealed (and usually unsigned), leaking changed file names and allowing a forged completion. (Lease breaks avoid this only because leases aren't granted on encrypted sessions.) | fixed (25792f0) |
| R14 | Medium | No per-session/connection caps on open handles, trees, or pended CHANGE_NOTIFYs; one inotify instance per connection (default `max_user_instances` 128) lets 128 clients exhaust notify for everyone. | partly fixed (25792f0): ≤ 16384 opens and 1024 trees per session, 1024 pended notifies per connection. Shared inotify: #55 |
| R15 | Medium | The packaged systemd unit runs as root, and paths are opened by plain joins (no `openat2(RESOLVE_BENEATH)`), so a symlink planted in a share by anyone with local write access reaches anything root can. | open: `*at()`/`openat2` resolution is #56; running the packaged unit as a dedicated user is the owner's call |
| R16 | Low | Encrypted frames called `tx.clear()`, discarding responses (and deferred notify finals) already batched for the connection in the same pass — pipelined sealed clients lost responses. | fixed (a1686f8) |
| R17 | Low | A second NEGOTIATE on a connection was accepted and reset dialect/cipher/preauth state under live sessions. | fixed (a1686f8) |
| R18 | Low | The decrypted inner SessionId wasn't tied to the transform's SessionId; a sealed frame naming another (unencrypted) session on the same connection could take the zero-copy READ path, whose plan (and dup'd fd) was then dropped — an fd leak and no response. | fixed (a1686f8) |
| R19 | Low | NTLMv2 proof compared with `!=` (not constant-time). Not exploitable (fresh challenge each attempt). | fixed (a1686f8) |
| R20 | Low | A zero-length LOCK became a POSIX "to EOF" lock, blocking every later lock on the file. | fixed (a1686f8) |
| R21 | Low | The share root itself could be deleted (CREATE `""` + delete-on-close on an empty share) or renamed. | fixed (a1686f8) |
| R22 | Low | Opening a FIFO or device node in a share (or via a symlink) blocked the worker thread in `open`. | fixed (a1686f8): non-blocking open, only regular files and directories |
| R23 | Low | Health endpoint: the 2 s timeout was per read, so a client trickling bytes could hold the single-threaded endpoint for hours. | fixed (a1686f8): 2 s deadline per request |
| R24 | Low | Lease table: handle-caching leases outlive CLOSE (grows until disconnect); a client reusing another's lease key overwrites its grant; the key ignores `st_dev`. | open: #57 |
| R25 | Low | Handle paths go stale when another handle renames a parent; `exists()` then `rename()` races a non-replacing rename. | partly fixed (a1686f8): non-replacing rename uses `RENAME_NOREPLACE`. Stale handle paths: #56 |
| R26 | Low | Directory snapshots stat every entry per handle; many handles on a huge directory multiply memory. | risk-accepted (bounded by the per-session open cap) |
| R27 | Low | CANCEL is exempt from signature checks, so an on-path attacker can cancel pended notifies. | risk-accepted (cancel only completes a pended notify early; the client re-issues it) |
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

## Verification

Each fix has a regression test that drives `process_frame` (or the reactor's
teardown hook) the way a client would: `replayed_message_id_disconnects`,
`second_negotiate_disconnects`, `read_only_tree_cannot_be_bypassed`,
`sessions_end_with_their_connection`, `binding_cannot_hijack_or_kill_sessions`,
`encrypted_session_hardening` (plaintext refused, sealed LOGOFF answered
sealed, batched bytes kept, foreign session in a sealed frame disconnects) and
`oversized_compound_disconnects`, plus `fuzzing::tests::fuzz_targets_smoke`.
They run in `cargo test` for the default, `kerberos` and
`backend-openssl kerberos` builds. libFuzzer ran all four targets on the build
box for 240 s each (2026-10-06): `process_frame` 0.72M execs, `ntlm` 104M,
`spnego` 260M, `transform` 5.9M, no crashes or panics.

Not verified against live clients in this pass: cifs and Windows mounts, with
and without `seal` and multichannel, should be re-run (bench/ scripts) before
the next release. The changes most likely to touch interop are the MessageId
window (R9), VALIDATE_NEGOTIATE_INFO checking (R8) and refusing plaintext on
encrypting sessions (R1).

## Not done

- **External review.** Still needed before the "don't expose 445 to the
  internet" caveat can go.
- Owner decisions: secure-by-default `require_signing` (R11) and `allow_guest`
  with Kerberos (R12), and a dedicated service user in the packaged unit (R15).
- Follow-ups: #55 (connection caps, timeouts, keepalive, shared inotify),
  #56 (`openat2` path resolution), #57 (lease table), #58 (interop).
