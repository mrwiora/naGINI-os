# Script delivery and secrets

## Servers

naGINI works with any server that serves the base64 ciphertext of a format-v2 script as the response
body of a plain `GET`. The script ID is the last path segment of the URL.

| Server | Script URL | Status |
|---|---|---|
| `naGINI-web` | `https://<server>/<short_id>` | current |
| `nagini-web2` (Node-RED) | `https://<server>/s/<short_id>` | planned, see `REWORK.md` |

## Encryption

- Scripts are encrypted in the publisher (format v2: `"NGN" 0x02` header used as AAD, AES-256-GCM,
  PBKDF2-SHA256 with 600,000 iterations). naGINI-web encrypts in the browser and accepts only v2
  payloads; the passphrase never reaches the server.
- naGINI decrypts with the passphrase (prompt without echo, `NAGINI_PASSPHRASE` or `-passphrase`) and
  executes the result as root. There is no unencrypted mode and no legacy format: anything that is not
  a v2 payload decrypting with the passphrase is refused. Scripts published in the old headerless
  format must be published again.

## Transport

- Only `https://` URLs are accepted; `http://` needs `-insecure-http`. Redirects may never change from
  HTTPS to HTTP (not even with `-insecure-http`), at most 5 redirects are followed.
- TLS 1.2 or newer, certificates are verified against the system CA store of the ISO.
- Before the download naGINI waits up to 30 seconds for NTP synchronisation, because certificate
  validation fails with a wrong clock.
- Network errors, HTTP 5xx and "certificate expired / not yet valid" (clock still wrong) are retried
  up to 10 times, 3 seconds apart, while DHCP and NTP settle. Unknown CAs, hostname mismatches and
  HTTP 4xx fail immediately.
- Downloads are limited to 16 MiB.

AES-GCM already detects any modification by someone who does not know the passphrase. TLS keeps the
URL path (= script ID = initial password) and the ciphertext away from the network.

## Password of the installed system

naGINI exports `PASSWORD` = the script ID (the last path segment of the URL, e.g. `1234affe` in
`https://<server>/1234affe`). Scripts set it as the initial password of the user account and expire it
with `passwd -e`, so it must be changed at the first login. naGINI prints it in the configuration
summary so the operator knows it.

Accepted risk: the script ID is part of the URL. Until the first login, anyone who knows the URL and
can reach the new system (e.g. via `sshd` with password authentication) can log in with it. SSH key
authentication only is planned as future work (see `REWORK.md`).

## Environment provided to the script

`DISK`, `INTERFACE`, `INTERFACEMAC`, `PARTITION1`, `PARTITION2`, `PASSWORD`.
