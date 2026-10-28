# The share URL

```text
https://spora.to/s/<token>?r=<host>:<port>[&r=<host>:<port>…]
```

The URL is self-contained: everything a client needs is inside it, and
possession of it is the only credential. Treat it accordingly.

- `<token>` is 60 characters of base64url: a version byte, the sharer's
  20-byte **cert hash** (the hash of the certificate its device presents,
  which the client checks), the share's 8-byte **share id**, and a 16-byte
  **secret** (proves to the sharer that the client was given the URL).
  The cert hash and share id make the share's routing hash, the
  connection id clients dial relays with. Replace the share with
  `spora share --fresh`.
- Each `?r=` names a relay endpoint, in the order clients should try them.
  IPv6 literals are bracketed: `?r=[2001:db8::1]:443`. Endpoints
  advertised with `--direct`, `--tcp-relay`, or `--nz-relay` are encoded
  here too, marked with their protocol.
- The `https://spora.to/s/` prefix makes the link clickable and lets the
  apps claim it. The CLI never contacts the website; if the link is opened
  in a browser without the app installed, the site shows an install page
  and does not log the token path.

Clients resolve relay hostnames at every connection attempt, prefer IPv6
addresses, and fall back through the list until one works, so a
multi-relay URL keeps working when a relay dies.
