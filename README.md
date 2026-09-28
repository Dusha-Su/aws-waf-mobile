# aws-waf-mobile

Mint **`aws-waf-token`** for the AWS WAF **Android SDK** (`client=android`).

This is the **HashcashPBKDF2** path used by the mobile SDK:

1. `GET …/inputs?client=android`
2. Build Android telemetry signals + SHA-256 checksum
3. Solve PBKDF2-HMAC-SHA256 (1000 rounds, 32-byte key, leading-zero-bit difficulty)
4. `POST …/verify` → token

TLS fingerprint is **OkHttp 4 / Android 13** via [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client). The token is bound to the IP (and TLS) that minted it — solve through the same proxy you will reuse.

Defaults point at CoinMarketCap’s Android WAF host. Pass `-endpoint` / `-domain` / `-app` for another Android SDK integration.

---

## Install

```bash
git clone https://github.com/Dusha-Su/aws-waf-mobile.git
cd aws-waf-mobile
go build -o aws-waf-mobile .
```

## CLI

```bash
./aws-waf-mobile -proxy 'http://user:pass@host:port'
```

Prints one token. Repeat with `-n 5`.

| flag | default | |
|---|---|---|
| `-proxy` | | `http://user:pass@host:port` (required unless `-direct`) |
| `-n` | `1` | how many tokens to mint |
| `-direct` | | mint without a proxy (leaks your IP) |
| `-endpoint` | CMC Android edge | `host/path` of the WAF SDK |
| `-domain` | `api.coinmarketcap.com` | `domain` field in the verify body |
| `-app` | `com.coinmarketcap.android` | `ApplicationID` signal |
| `-listen` | | if set (e.g. `:8192`), serve HTTP instead of CLI mint |

### HTTP API

```bash
./aws-waf-mobile -listen :8192
```

`POST /solve`

```json
{ "proxy": "http://user:pass@host:port" }
```

```json
{ "success": true, "token": "…", "token_len": 338 }
```

Optional body fields: `endpoint`, `domain`, `app`, `direct`.

---

## Go API

```go
package main

import (
	"fmt"
	"log"

	"github.com/Dusha-Su/aws-waf-mobile/solver"
)

func main() {
	tok, err := solver.Mint(solver.Options{
		Proxy: "http://user:pass@host:port",
	})
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(tok)
}
```

---

## Notes

- Challenge type is **HashcashPBKDF2**, not the browser NetworkBandwidth / Zoey `mp_verify` path.
- Empty signal values are intentional — the SDK still ships the full name list; checksum is SHA-256 of the joined `Present` strings.
- If minting starts failing, the host rotated the WAF JS / difficulty / challenge type. Check `/inputs?client=android`.
