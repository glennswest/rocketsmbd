# Test vectors

| File | What | Source |
|---|---|---|
| `pac-w2003.bin` | Windows Server 2003 PAC (machine account `W2003FINAL$`, domain `WIN2K3THINK`) | `saved_pac` in MIT krb5 `src/lib/krb5/krb/t_pac.c`, copied there with permission from Samba's torture suite |
| `pac-w2008-s4u.bin` | Windows Server 2008 S4U2Self PAC (user `w2k8u`, domain `ACME`, Domain Users) | `s4u_pac_regular` in the same file |

MIT krb5 is MIT-licensed (BSD-style); the vectors are used unchanged as the
raw `PACTYPE` bytes. Used by the `pac.rs` and `smb2` unit tests (#40).
