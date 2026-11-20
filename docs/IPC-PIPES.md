# IPC$ named pipes → an RPC backend (#83)

A Windows domain join speaks SAMR, LSARPC and NETLOGON as DCE/RPC over SMB
named pipes on `IPC$` (`ncacn_np`: `\PIPE\samr`, `\PIPE\lsarpc`,
`\PIPE\netlogon`). rocketsmbd does not implement those RPC interfaces. It
forwards each opened pipe to a backend over a Unix stream socket. The
backend is irondirectory's `iron-rpcd` (irondirectory#53), which serves the
interfaces. The backend gets the DCE/RPC bytes unchanged, after a short
preamble that says who the SMB session authenticated as and gives it the
session key.

## Configuration

```toml
[ipc]
backend = "/run/iron-rpcd/ncacn_np.sock"   # absolute path of a Unix stream socket
pipes = ["samr", "lsarpc", "netlogon"]     # the default; case-insensitive
```

Without `[ipc]`, a CREATE on `IPC$` gets `STATUS_OBJECT_NAME_NOT_FOUND`, as
does any pipe name not in `pipes`. This applies to CREATEs that pass the
checks under "Who may open a pipe" below; any other CREATE gets
`STATUS_ACCESS_DENIED`. Only Unix sockets are accepted, because the
preamble carries the session key. A TCP backend would send that key in
cleartext.

## What the client sees

| Request on `IPC$` | Behavior |
|---|---|
| CREATE `samr` (also `\samr`, `PIPE\samr`, `\PIPE\samr`) | Connects to `backend` (non-blocking) and sends the preamble. Then it answers like an opened file: FILE_OPENED, FILE_ATTRIBUTE_NORMAL, AllocationSize 4096, no oplock or lease. An unreachable backend or a full listen backlog gives `STATUS_PIPE_NOT_AVAILABLE`. |
| WRITE | The bytes go to the backend unchanged. The Offset is ignored, because a pipe is a stream. If the socket can't take the whole write right now, the pipe breaks (`STATUS_PIPE_BROKEN`) rather than leave half a message in the stream. |
| READ | Returns one message. |
| IOCTL `FSCTL_PIPE_TRANSCEIVE` | Writes the input, then returns one message (up to MaxOutputResponse). |
| CLOSE | Shuts the socket down, so the backend sees EOF. A read waiting on the pipe ends with `STATUS_CANCELLED`. |
| CANCEL of a waiting read | The read ends with `STATUS_CANCELLED`. |
| TREE_DISCONNECT, LOGOFF, connection drop | The tree's or session's pipes are closed as above. |
| IOCTL VALIDATE_NEGOTIATE_INFO, QUERY_NETWORK_INTERFACE_INFO | Answered as before. |
| any other command | `STATUS_ACCESS_DENIED`. |

**Messages.** RPC pipes are message-mode. rocketsmbd cuts the backend's byte
stream into messages at DCE/RPC fragment boundaries, using `frag_length` in the
16-byte connection-oriented header (C706 §12.6.3, with byte order from
`drep[0]`).
- When the client's buffer is shorter than the fragment, it gets the first
  part with `STATUS_BUFFER_OVERFLOW` and the rest on the next READ.
- A fragment that has only partly arrived is held until the rest comes.
- If the backend sends anything that is not a version-5 PDU header, the pipe
  breaks.

**Waiting.** When no complete message has arrived, the READ or TRANSCEIVE
gets an interim `STATUS_PENDING`. The worker's io_uring ring polls a dup of
the backend socket, and the final response is sent once the message arrives.
The final response is signed or sealed like any other response on the
session. The reactor never blocks on the backend. Each pipe can have one
waiting read at a time; a second read gets `STATUS_PIPE_BUSY`. One connection
can have at most 64 reads waiting, and one session can have at most 64 open
pipes.

**Who may open a pipe.**
- The session must be authenticated. Guest and anonymous sessions get
  `STATUS_ACCESS_DENIED`.
- Every request on a pipe (CREATE, READ, WRITE, IOCTL, CLOSE) must be
  integrity-protected: signed (and the signature verified), or sealed with
  SMB3 encryption. An unsigned, unsealed request gets `STATUS_ACCESS_DENIED`,
  even on a session where signing is optional.

rocketsmbd does not decide which RPC operations a user may call. The backend
decides, from the identity in the preamble.

## The preamble (version 1)

rocketsmbd writes this once, right after connecting and before the first
client byte. All integers are little-endian. A *str* is a u16 byte length
followed by that many bytes (UTF-8 for text).

| Field | Type | Meaning |
|---|---|---|
| magic | 8 bytes | `RSMBPIPE` |
| version | u16 | `1` |
| reserved | u16 | `0` |
| length | u32 | bytes of everything below |
| flags | u16 | `0x1` the CREATE was signed · `0x2` it was sealed (SMB3 encryption) · `0x4` the session is Kerberos (the SIDs come from the KDC-signed PAC) |
| dialect | u16 | negotiated SMB dialect, e.g. `0x0311` |
| pipe | str | lowercased pipe name, e.g. `samr` |
| session_key | str | 16 bytes: the key RPC treats as the connection's session key (below) |
| user | str | the authenticated name: a Kerberos principal (`alice@AD.EXAMPLE`) or an NTLM user from rocketsmbd's `[[user]]` list |
| domain | str | NetBIOS domain from the PAC (empty without a PAC) |
| user_sid | str | user SID from the PAC, `S-1-5-21-…` (empty without a PAC) |
| group_count | u16 | number of group SIDs that follow |
| groups | str × group_count | group SIDs from the PAC (primary group, GroupIds, ExtraSids, resource groups) |

After the preamble, the stream carries only DCE/RPC PDUs, in both directions.
rocketsmbd sends no acknowledgement and expects none. To refuse a pipe, the
backend closes the socket, and the client's next read or write gets
`STATUS_PIPE_BROKEN`.

**session_key** is the key Samba also gives its RPC server for an `ncacn_np`
connection:
- SMB 3.1.1: Session.ApplicationKey, KDF(SessionKey, `"SMBAppKey\0"`, the
  session's preauth integrity hash).
- SMB 3.0 and 3.0.2: KDF(SessionKey, `"SMB2APP\0"`, `"SmbRpc\0"`). Both are
  from MS-SMB2 3.3.5.5.3.
- SMB 2.x: the session key itself.

SAMR's `SamrSetInformationUser2` (UserInternal8 / AES,
`SAMPR_ENCRYPTED_PASSWORD_AES`) encrypts the new password with this key.

**Identity without Kerberos.** An NTLM session (flag `0x4` clear) carries no
SIDs, only the user name, which comes from rocketsmbd's own user list and not
from the domain. A backend should not give such a session domain-admin rights.

## Tests

- `src/pipe.rs`: framing (both byte orders, partial fragments, a short
  buffer, garbage), the preamble layout, and an unreachable backend.
- `src/smb2/ipc.rs`: drives `process_frame` on a signed 3.1.1 session with a
  fake backend socket. It covers the exact preamble bytes (app key and user),
  a TRANSCEIVE that pends and then completes signed, WRITE+READ with
  BUFFER_OVERFLOW, PIPE_BUSY, CANCEL, CLOSE (backend sees EOF), unsigned and
  guest refusal, a backend that dies mid-read, and a backend that is gone.
- `rocketsmbd-test` `ipc-pipe-forward` (short suite) runs the real server and
  reactor with the test container's SMB client and a fake backend. The client
  derives the application key itself and checks it against the preamble.

Not yet run against a real client stack (impacket `ncacn_np`, Windows
`Add-Computer`) or against `iron-rpcd`, which does not have the socket side
yet (irondirectory#53). A Windows join needs stormcentral#465.
