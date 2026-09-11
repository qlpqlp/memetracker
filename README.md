# MemeTracker

![MemeTracker logo](static/logo.png)

MemeTracker allows you to detect payments in ~3 seconds so you can use it in your business to accept Dogecoin payments, detect them quickly, and confirm later while your customer sits down and enjoys their coffee.

MemeTracker is a **Dogecoin mempool watcher**: it connects to the public P2P network (or your own node), requests the mempool, and follows `inv` / `getdata` / `tx` traffic. **Mempool is always first priority.** Headers/tip-block scans are only a backup when a payment skips mempool relay and is mined immediately. When a transaction pays one of your tracked **P2PKH** addresses (classic base58, e.g. mainnet addresses starting with `D`), it records the txid, timestamp, DOGE amount, and double-spend flag, and can call an optional HTTP callback.

## How it works

1. **P2P (mempool, priority 1)** - Several parallel sessions (default 3, configurable) connect to DNS seeds or `P2P_HOST`, complete version handshake, send `mempool`, then handle `inv` (transaction inventory), request bodies with `getdata`, and parse `tx` payloads. This path must not be starved.
2. **P2P (header backup, priority 2)** - Tracks tip headers (`sendheaders` / `getheaders`), persists tip to `{storage}/header_tip.json`, and only scans **recent tip block bodies** when mempool is quiet. Purpose: catch watched payments that missed mempool relay and were mined immediately. Not a full historical block download.
3. **Parsing** - Outputs are scanned for P2PKH / P2SH / v0 P2WPKH patterns; amounts going to a watched **hash160** are summed per transaction.
4. **Double-spend detection** - Inputs are tracked by outpoint (`prev_txid:vout`) during live mempool observation. If multiple txids spend the same outpoint in the active tracking window, those tx rows are marked as `double_spent = true`. Block-scan hits do not invent mempool conflicts.
5. **Storage** - Each watched address has a JSON file under `{storage}/addresses/{hash160}.json`. Transactions are capped per address (`list_limit`) and addresses expire after `retention_days` without a refresh via `GET/POST /track/<address>`.
6. **HTTP** - A local server (default port **33555**) serves the dashboard, JSON APIs, and `/track/` for automation.

Observed **mempool tx count** in the UI is the number of **unique txids** recently seen on the wire (from `inv` and `tx`), which approximates relay visibility, not necessarily the same as `getrawmempool` on a full node. Dashboard **header safeguard** fields show tip hash/time, headers kept, blocks scanned, and payments first seen via blocks.

## Quick start

### Run from source

```bash
go run .
```

### Run a release binary

Download a build from your `dist/` folder (after running the release script), from GitHub Releases, or from CI artifacts. Then:

```bash
# Windows (example)
.\memetracker-v1.0.0-windows-amd64.exe

# Linux / macOS
chmod +x memetracker-v1.0.0-linux-amd64
./memetracker-v1.0.0-linux-amd64
```

On first run the process **opens your browser** to the local dashboard (disable with `MTR_NO_BROWSER=1`). The **P2P mempool watcher stays off** until either:

1. You fill in **Start MemeTracker** on the home page and click **Start** (writes `memetracker_config.json` and starts P2P), or  
2. A complete **`memetracker_config.json`** already exists when the app starts (same rules as below), in which case P2P **auto-starts** and the "start" banner stays hidden.

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
  "api_allowed_ips": [],
  "api_token": ""
}
```

- **`api_allowed_ips`**: optional array of IPv4/IPv6 addresses or CIDR strings (e.g. `"192.168.1.0/24"`). **Omitted or empty** with no token => open access. If non-empty, only listed addresses can open the **web UI** and call `/api/*` / `/track/*` without a token (include `127.0.0.1` for local UI). You can also POST `/api/allowlist`.
- **`api_token`**: optional URL access token. When set, open `http://HOST/{api_token}/` for the dashboard (UI calls `/{token}/api/...`). Also `/{token}/track/...` and `/{token}/api/...` from any IP (token bypasses the allowlist). Token-only (no IP list) requires the token prefix for UI and API. Do not use reserved names (`api`, `track`, `healthz`, `logo.png`). Env `MTR_API_TOKEN` overrides the file value on process start.

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
| `MTR_P2P_PARALLEL` / `P2P_PARALLEL` | `3` | Parallel P2P workers (1-8) |
| `MTR_P2P_LOG` / `P2P_LOG` | `1` | P2P log verbosity `0`-`2` |
| `MTR_CONFIG_PATH` | _(see above)_ | Full path to `memetracker_config.json` |
| `MTR_NO_BROWSER` | _(empty)_ | Set to `1` to skip opening the browser |
| `MTR_NO_AUTOSTART` | _(empty)_ | Set to `1` to **not** auto-start P2P even if the config file is complete |
| `MTR_API_TOKEN` | _(empty)_ | Optional URL access token; overrides `api_token` from config on start |
| `MTR_TRUST_XFF` | _(empty)_ | Set to `1` so API IP checks use the first `X-Forwarded-For` address (only if MemeTracker is behind a **trusted** reverse proxy) |

If `MTR_STORAGE_DIR` is unset:

- **Windows:** `%AppData%\MemeTracker\data`
- **Other:** `~/.memetracker/data` (fallback `./memetracker-data`)

**Runtime settings:** changing list limit and retention from the web UI writes `settings.json` in the storage directory and applies immediately.

## Web interface

- **Start MemeTracker** - Shown while P2P is off: full-parameter form and **Start** (writes `memetracker_config.json`). Hidden when P2P is running or after a complete config auto-starts the watcher.
- **Dashboard** - Counts: P2P on/off, tracked addresses, stored tx rows, mempool ids seen, connected workers, plus header tip height/hash (copyable), headers kept, blocks scanned, and confirmed-from-block hits.
- **Configuration** - Edit stored tx cap and retention; view effective env-derived options (network, bind, P2P).
- **Track address** - Add a P2PKH address (same as `/track/<address>`).
- **Tracked addresses** - Table with **tracked since** and **last refresh** timestamps; **Remove** deletes the address and **all** stored txs for it.
- **Transactions** - All detected rows with time, address, txid, DOGE amount, and conflict status. Rows flagged as conflicting show a **Double spent detected** badge. **Remove** drops one row and clears the dedupe cache for that txid so it could be stored again if seen later.
- **Peers & mempool** - Per-worker peer address and connected/idle state; mempool unique tx count.
- **API access** - Optional IP allowlist and optional URL token (`/{token}/track/...`).
- **Help & API docs** - In-app explanation of mempool watching, header safeguard, double-spend flags, and curl examples.

Favicon and header use the official Silly Pups MemeTracker asset [static/logo.png](static/logo.png) (same file as `silly-pups/memetracker/logo.png`).

## HTTP API (selection)

| Method | Path | Description |
| ------ | ---- | ----------- |
| GET | `/` | Web dashboard |
| GET | `/healthz` | Health JSON |
| GET | `/api/mempool?offset=&limit=` | Paginated newest-first mempool txids (`limit` max 100). Prefer this over dumping thousands into `/api/status`. |
| POST | `/api/start` | Body: full `memetracker_config.json` shape; saves file and starts P2P (or returns `restart_required` if `storage_dir` changed) |
| POST | `/api/stop` | Stop P2P workers and the Dogebox metrics ticker; HTTP UI keeps running. **Note:** if a complete `memetracker_config.json` exists, the next process restart will auto-start P2P again unless you remove that file or set `MTR_NO_AUTOSTART=1`. |
| POST | `/api/allowlist` | JSON `{ "api_allowed_ips": ["127.0.0.1"], "api_token": "secret" }`. Empty IP array => allow all IPs when no token prefix is used. Empty `api_token` clears the token. Writes `memetracker_config.json`. |
| GET | `/api/config` | `{ list_limit, retention_days }` |
| POST | `/api/config` | JSON body: `{ "list_limit": 50, "retention_days": 14 }` |
| DELETE | `/api/addresses/{hash160_hex}` | Untrack address and delete its file |
| DELETE | `/api/transactions?txid=...&hash160_hex=...` | Remove one stored tx row |
| GET/POST | `/track/{P2PKH}` | Start or refresh tracking (503 if P2P not running); optional `callback` query / `X-Callback-Url` |
| GET/POST | `/{api_token}/` | Web UI with token (same as `/`); JS calls `/{token}/api/...` |
| GET/POST | `/{api_token}/track/{P2PKH}` | Same as `/track/...` when `api_token` is configured; **bypasses IP allowlist** |
| * | `/{api_token}/api/...` | Same as `/api/...` with token prefix; **bypasses IP allowlist** |

`/api/status` transaction rows include:

- `txid`
- `address`
- `amount_doge`
- `datetime`
- `hash160_hex`
- `double_spent` (`true` when a conflicting spend was detected in the current live mempool tracking window)
- `confirmed` (`true` once the payment was seen in a scanned block)
- `confirmations` (integer 0-5: header/block depth after inclusion; stays at 5 once deeper)
- `block_height` (inclusion height when known)

`/api/status` also includes `header_safeguard`:

- `tip_hash`
- `tip_height` (number when known, otherwise null)
- `tip_time_utc`
- `headers_kept`
- `headers_seen_total`
- `blocks_scanned`
- `confirmed_hits` (watched payments newly stored from block scans)
- `pending_block_fetches`
- `retention` (e.g. `24h0m0s`)
- `persist_path` (usually `{storage}/header_tip.json`)
- `resumed_from_disk`

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
- `SHA256SUMS` - `sha256sum` format for all binaries in that folder

### GitHub Actions auto release

Workflow [`.github/workflows/release.yml`](.github/workflows/release.yml):

- **Push to `main` / `master`**: computes the next patch version from the latest `v*` tag (or starts at `1.0.0`), creates an annotated tag, cross-compiles all platforms, writes `SHA256SUMS`, and publishes a GitHub Release with the binaries.
- **Push of tag `v*`**: builds and publishes (or updates) that version's Release.
- **`workflow_dispatch`**: optional `version` input (without `v`) to force a specific release tag.

## Authors

- **Paulo Vidal** - [@inevitable360](https://x.com/inevitable360) · [Dogecoin Foundation Dev](https://foundation.dogecoin.com)
