# rocketsmbd tests on a node

The stormcos test container (stormcentral `docs/test-standard.md`, #44).
`test/build.sh` builds two static musl binaries, `rocketsmbd` and `/test`
(this crate), and `test/Containerfile` copies them into a `FROM scratch`
image. The Job runs `/test <suite>`.

`/test` starts `/rocketsmbd` on loopback (free ports, `workers = 2`) with a
generated config: shares `data` (read-write), `ro` (read-only) and `extra`,
one NTLM user with a random password made at start, guest allowed, leases
on, and the health endpoint. It drives the server with the SMB2/3 client in
`src/client.rs`, whose NTLMv2, key derivation, signing and AEAD transform are
rocketsmbd's own library code. It prints one JSON line per test, then a
summary. Exit codes: 0 all passed, 1 a test failed, 2 could not run.

| suite | tests |
|---|---|
| short | `server-start`, `guest-write-read-dir` (3.0.2 guest, 4 MiB through the zero-copy READ path, sha512-checked, directory listing), `ntlmv2-signed-311` (every request signed, every reply verified), `sealed-aes128gcm` (sealed round trip; plaintext on a sealed session refused), `lease-break-on-write` (A holds an R/H lease, B writes, A gets the break), `healthz` |
| medium | short + `wrong-password-refused`, `read-only-share` (reads served; writes, FILE_CREATE and FILE_OPEN_IF refused), `sealed-all-ciphers` (AES-128/256-GCM/CCM), `large-file-64mib`, `parallel-clients` (16 at once, signed and guest), `replay-disconnects` (a replayed request closes the connection), `healthz-503-when-share-gone` |
| long | short + medium + `waves-no-leak`: waves of 8–32 clients that connect, round-trip 1 MiB and drop without LOGOFF, until `STORM_TIMEOUT` minus a minute. Fails if the server's fds or RSS grow, or a wave gets much slower than the first |

It needs nothing from the node or the API, only an io_uring kernel (see
`requires.toml`), so it runs on every test machine. Run it on the build box
without an image:

```sh
sc-build 'test/build.sh && ROCKETSMBD_BIN=test/out/rocketsmbd test/out/test short'
```

`ROCKETSMBD_BIN` points at the server (default `/rocketsmbd`); `TMPDIR`
(default `/tmp`) holds the run's shares and the server log, which is removed
at the end and copied to `/results/rocketsmbd.log` if `/results` exists.
