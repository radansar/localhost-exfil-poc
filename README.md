# localhost exfil PoC

Three browser-to-localhost exfil channels tested on Safari 26.5 (macOS 26.5)

| Channel | How | Safari | Cert needed |
|---|---|---|---|
| `<img>` HTTP | Identifier in URL query string; Safari loads HTTP images from an HTTPS page (passive mixed-content) | ✅ | No |
| TLS SNI | Identifier hex-encoded in the SNI hostname; extracted from the raw ClientHello before any cert check | ✅ | No |
| HTTPS fetch | Full bidirectional HTTP; Safari has no gate on HTTPS-to-localhost from a public HTTPS origin | ✅ | Yes — domain must resolve to 127.0.0.1 with a browser-trusted cert |

## Run

**Channels 1 + 2 (no cert):**
```sh
python3 server.py
```

**All three channels:**
```sh
python3 server.py --cert cert.pem --key key.pem
```

Host `index.html` on any public HTTPS origin, open in Safari or Chrome, enter an identifier, click Send.

## Channel 3 — cert setup

**Local testing with mkcert:**
```sh
brew install mkcert && mkcert -install
mkcert -cert-file cert.pem -key-file key.pem localhost 127.0.0.1
```
Use `localhost:8443` as the domain in the page.

**Production:** register a domain (e.g. `mylocaltest.xyz`), set its A record to `127.0.0.1`, obtain a Let's Encrypt certificate. Pass those cert/key files to `server.py`. No local setup needed on the target machine — the cert is already trusted by all browsers.

## Expected output

```
[15:42:01] IMG   src=127.0.0.1:51200   id = 'hello-from-img'
[15:42:04] SNI   hostname = id-68656c6c6f...sni.localtest.me   id = 'hello-from-sni'
[15:42:07] HTTPS src=127.0.0.1:51202   id = 'hello-from-https'
```
