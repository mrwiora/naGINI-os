# Script delivery and secrets

- Scripts are composed in nagini-web2, encrypted (format v2: `"NGN" 0x02` header, AES-256-GCM,
  PBKDF2-SHA256 600k) with a new random passphrase per publish, and served as base64 ciphertext at
  `https://<server>/s/<short_id>` by the same service. The passphrase is shown once and never stored.
- `naGINI` downloads the ciphertext, decrypts it with the passphrase (prompt, `NAGINI_PASSPHRASE`
  or `-passphrase`) and executes it as root. If decryption fails, nothing is executed.
- There is no unencrypted mode and no legacy format: anything that is not a v2 payload decrypting
  with the passphrase is refused. `http://` URLs are refused unless `-insecure-http` is given.

## Password of the installed system

naGINI exports `PASSWORD` = the script ID (the last path segment of the URL, e.g. `1234affe` in
`https://<server>/s/1234affe`). Scripts set it as the initial password of the user account and expire it
with `passwd -e`, so it must be changed at the first login. naGINI prints it in the configuration
summary so the operator knows it.

Accepted risk: the script ID is part of the URL. Until the first login, anyone who knows the URL and
can reach the new system (e.g. via `sshd` with password authentication) can log in with it. SSH key
authentication only is planned as future work (see `REWORK.md`).

## Environment provided to the script

`DISK`, `INTERFACE`, `INTERFACEMAC`, `PARTITION1`, `PARTITION2`, `PASSWORD`.
