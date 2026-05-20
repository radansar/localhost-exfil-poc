# localhost exfil PoC

Two browser-to-localhost exfil channels that require no certificate and no local configuration.

| Channel | How
|---|---|---|
| `<img>` HTTP | Identifier in URL query string; Safari loads HTTP images from localhost even from an HTTPS page
| TLS SNI | Identifier hex-encoded in the SNI hostname; extracted from the raw TLS ClientHello before any cert check |

## Run

```sh
python3 server.py
```

Host `index.html` on any public HTTPS origin (GitHub Pages, Cloudflare Tunnel, etc.), open it in Safari or Chrome, enter an identifier, click Send.

Expected output:

```
[15:42:01] IMG  src=127.0.0.1:51200
  id = 'hello-from-img'

[15:42:04] SNI  src=127.0.0.1:51201
  hostname = id-68656c6c6f2d66726f6d2d736e69.sni.localtest.me
  id       = 'hello-from-sni'
```
