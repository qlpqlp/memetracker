# MemeTracker

![MemeTracker logo](static/logo.png)

MemeTracker allows you to detect payments in ~3 seconds to allow it to use on your buisness to accept Dogecoin Payments and at least be able to detect them quicker and confirm it later while your custumer sits down and enjoys his coffe.

MemeTracker is a **Dogecoin mempool watcher**: it connects to the public P2P network (or your own node), requests the mempool, and follows `inv` / `getdata` / `tx` traffic. It **does not** download blocks or headers. When a relayed transaction pays one of your tracked **P2PKH** addresses (classic base58, e.g. mainnet addresses starting with `D`), it records the txid, timestamp, DOGE amount, and double-spend flag, and can call an optional HTTP callback.

## How it works

1. **P2P** — Several parallel sessions (default 3, configurable) connect to DNS seeds or `P2P_HOST`, complete version handshake, send `mempool`, then handle `inv` (transaction inventory), request bodies with `getdata`, and parse `tx` payloads.
2. **Parsing** — Outputs are scanned for P2PKH / P2SH / v0 P2WPKH patterns; amounts going to a watched **hash160** are summed per transaction.
3. **Double-spend detection** — Inputs are tracked by outpoint (`prev_txid:vout`) during live mempool observation. If multiple txids spend the same outpoint in the active tracking window, those tx rows are marked as `double_spent = true`.
4. **Storage** — Each watched address has a JSON file under `{storage}/addresses/{hash160}.json`. Transactions are capped per address (`list_limit`) and addresses expire after `retention_days` without a refresh via `GET/POST /track/<address>`.
5. **HTTP** — A local server (default port **33555**) serves the dashboard, JSON APIs, and `/track/` for automation.

Observed **mempool tx count** in the UI is the number of **unique txids** recently seen on the wire (from `inv` and `tx`), which approximates relay visibility—not necessarily the same as `getrawmempool` on a full node.

## Quick start

### Run from source

```bash
go run .
```

### Run a release binary

Download a build from your `dist/` folder (after running the release script) or from your Git hosting releases page. Then:

```bash
# Windows (example)
.\memetracker-v1.0.0-windows-amd64.exe

# Linux / macOS
chmod +x memetracker-v1.0.0-linux-amd64
./memetracker-v1.0.0-linux-amd64
```

On first run the process **opens your browser** to the local dashboard (disable with `MTR_NO_BROWSER=1`). The **P2P mempool watcher stays off** until either:

1. You fill in **Start MemeTracker** on the home page and click **Start** (writes `memetracker_config.json` and starts P2P), or  
2. A complete **`memetracker_config.json`** already exists when the app starts (same rules as below), in which case P2P **auto-starts** and the “start” banner stays hidden.

Config file location (unless overridden):

- `MTR_CONFIG_PATH`, or  
- `{MTR_STORAGE_DIR or default}/memetracker_config.json`

Example `memetracker_config.json` (all fields required for auto-start; `p2p_host` may be `""`):

```json
{
  "http_port": 33555,
  "http_bind": "0.0.0.0",
  "network": "mainnet",
  "storage_dir": "",
  "list_limit": 10,
  "retention_days": 7,
  "p2p_host": "",
  "p2p_port": 22556,
  "p2p_parallel": 3,
  "p2p_log": 1,
  "api_allowed_ips": []
}
```

- **`api_allowed_ips`**: optional array of IPv4/IPv6 addresses or CIDR strings (e.g. `"192.168.1.0/24"`). **Omitted or empty** ⇒ any client IP may call `/api/*` and `/track/*`. If non-empty, only listed addresses can use those paths (include `127.0.0.1` if you use the local web UI against a locked-down API). You can also POST `/api/allowlist` with `{ "api_allowed_ips": ["127.0.0.1"] }`.

Use `"storage_dir": ""` or omit to keep the default data directory. If you change `storage_dir` to another path while the app is already running with a different data directory, the UI saves the file and asks you to **restart** once.

`GET /track/...` and adding addresses in the UI only work while **P2P is running** (after Start or auto-start).

### Environment variables

| Variable | Default | Meaning |
| -------- | ------- | ------- |
| `MTR_HTTP_PORT` / `PUBLIC_PORT` | `33555` | HTTP listen port |
| `MTR_HTTP_BIND` / `DBX_PUP_IP` | `0.0.0.0` | HTTP bind address |
| `MTR_STORAGE_DIR` | OS-specific user config path (see below) | Data directory |
| `MTR_NETWORK` / `NETWORK` | `mainnet` | `mainnet` or `testnet` |
| `MTR_LIST_LIMIT` / `LIST_LIMIT` | `10` | Max stored txs per address |
| `MTR_RETENTION_DAYS` / `RETENTION_DAYS` | `7` | Drop address if not refreshed for N days |
| `MTR_P2P_HOST` / `P2P_HOST` | _(empty)_ | Force a single peer host (else DNS seeds) |
| `MTR_P2P_PORT` / `P2P_PORT` | `22556` | P2P port |
| `MTR_P2P_PARALLEL` / `P2P_PARALLEL` | `3` | Parallel P2P workers (1–8) |
| `MTR_P2P_LOG` / `P2P_LOG` | `1` | P2P log verbosity `0`–`2` |
| `MTR_CONFIG_PATH` | _(see above)_ | Full path to `memetracker_config.json` |
| `MTR_NO_BROWSER` | _(empty)_ | Set to `1` to skip opening the browser |
| `MTR_NO_AUTOSTART` | _(empty)_ | Set to `1` to **not** auto-start P2P even if the config file is complete |
| `MTR_TRUST_XFF` | _(empty)_ | Set to `1` so API IP checks use the first `X-Forwarded-For` address (only if MemeTracker is behind a **trusted** reverse proxy) |

If `MTR_STORAGE_DIR` is unset:

- **Windows:** `%AppData%\MemeTracker\data`
- **Other:** `~/.memetracker/data` (fallback `./memetracker-data`)

**Runtime settings:** changing list limit and retention from the web UI writes `settings.json` in the storage directory and applies immediately.

## Web interface

- **Start MemeTracker** — Shown while P2P is off: full-parameter form and **Start** (writes `memetracker_config.json`). Hidden when P2P is running or after a complete config auto-starts the watcher.
- **Dashboard** — Counts: P2P on/off, tracked addresses, stored tx rows, mempool ids seen, connected workers.
- **Configuration** — Edit stored tx cap and retention; view effective env-derived options (network, bind, P2P).
- **Track address** — Add a P2PKH address (same as `/track/<address>`).
- **Tracked addresses** — Table with **tracked since** and **last refresh** timestamps; **Remove** deletes the address and **all** stored txs for it.
- **Transactions** — All detected rows with time, address, txid, DOGE amount, and conflict status. Rows flagged as conflicting show a **Double spent detected** badge. **Remove** drops one row and clears the dedupe cache for that txid so it could be stored again if seen later.
- **Peers & mempool** — Per-worker peer address and connected/idle state; mempool unique tx count.

Favicon and header use the official Silly Pups MemeTracker asset [static/logo.png](static/logo.png) (same file as `silly-pups/memetracker/logo.png`).

## HTTP API (selection)

| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/` | Web dashboard |
| GET | `/healthz` | Health JSON |
| GET | `/api/status` | Full dashboard payload; includes `p2p_running`, `full_config`, `memetracker_config_path`, and `transactions[].double_spent` |
| POST | `/api/start` | Body: full `memetracker_config.json` shape; saves file and starts P2P (or returns `restart_required` if `storage_dir` changed) |
| POST | `/api/stop` | Stop P2P workers and the Dogebox metrics ticker; HTTP UI keeps running. **Note:** if a complete `memetracker_config.json` exists, the next process restart will auto-start P2P again unless you remove that file or set `MTR_NO_AUTOSTART=1`. |
| POST | `/api/allowlist` | JSON `{ "api_allowed_ips": ["127.0.0.1", "10.0.0.0/8"] }`. Empty array ⇒ allow all. Writes `memetracker_config.json`. |
| GET | `/api/config` | `{ list_limit, retention_days }` |
| POST | `/api/config` | JSON body: `{ "list_limit": 50, "retention_days": 14 }` |
| DELETE | `/api/addresses/{hash160_hex}` | Untrack address and delete its file |
| DELETE | `/api/transactions?txid=...&hash160_hex=...` | Remove one stored tx row |
| GET/POST | `/track/{P2PKH}` | Start or refresh tracking (503 if P2P not running); optional `callback` query / `X-Callback-Url` |

`/api/status` transaction rows include:

- `txid`
- `address`
- `amount_doge`
- `datetime`
- `hash160_hex`
- `double_spent` (`true` when a conflicting spend was detected in the current live mempool tracking window)

Verify checksums after download:

```bash
sha256sum -c SHA256SUMS
```

## Building release binaries and checksums

From the repository root:

**Windows (PowerShell):**

```powershell
$env:MTR_VERSION = "1.0.0"   # optional
powershell -ExecutionPolicy Bypass -File scripts/build-release.ps1
```

**Linux / macOS:**

```bash
MTR_VERSION=1.0.0 bash scripts/build-release.sh
```

Artifacts land in `dist/`:

- `memetracker-v{version}-{goos}-{goarch}(.exe)`
- `SHA256SUMS` — `sha256sum` format for all binaries in that folder

Upload the `dist` contents (or release assets) to Git; keep `SHA256SUMS` alongside the binaries.

## Legacy code

`fetch.go` is kept in the repo for reference but is **excluded from the build** (`//go:build ignore`). The runnable program is **`main.go`** only.

## Authors

- **Paulo Vidal** — [@inevitable360](https://x.com/inevitable360) · [Dogecoin Foundation Dev](https://foundation.dogecoin.com)
