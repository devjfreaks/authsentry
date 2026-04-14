# AuthSentry

**Suspicious login detector for auth logs.** AuthSentry parses authentication log files, enriches IPs with [geolocation](https://ipgeolocation.io/documentation/ip-location-api.html) and [security intelligence](https://ipgeolocation.io/documentation/ip-security-api.html) via [ipgeolocation.io](https://ipgeolocation.io), and produces risk-scored HTML or JSON reports.

A login from a DigitalOcean IP with a VPN flag is almost certainly a credential stuffing attack.  
A login from the same country as all previous sessions is probably fine.  
AuthSentry tells you which is which.

---

## Features

| Feature | Detail |
|---|---|
| **Production-safe streaming** | Line-by-line parsing, bounded memory, handles GB-scale files |
| **Parallel processing** | Configurable worker pool (`--workers`) |
| **Rate limiting** | Token-bucket limiter, configurable RPS (`--rps`) |
| **Intelligent caching** | SQLite cache (`cache.db`), 24h TTL, 90%+ API call reduction |
| **Deduplication** | In-memory dedup within a run (`--dedupe-cap`) |
| **Risk scoring** | `HOSTING + VPN + ThreatScore` → `CRITICAL / HIGH / MEDIUM / LOW` |
| **Multi-format parsing** | Django, Laravel, Rails, Apache, Nginx, raw |
| **Output formats** | Interactive HTML report or JSONL |
| **Docker support** | Multi-stage image, non-root, works in CI/CD |

---

## Quick Start

### From Binary

```bash
# Linux amd64
curl -Lo authsentry https://github.com/devjfreaks/authsentry/releases/latest/download/authsentry-linux-amd64
chmod +x authsentry

# Run against your log
export IPGEOLOCATION_API_KEY=your_key_here
./authsentry /var/log/auth.log --enrich-all --out report.html
```

### From Source

```bash
# Requires Go 1.22+ and gcc (for sqlite3)
git clone https://github.com/devjfreaks/authsentry.git
cd authsentry
make build

./authsentry /var/log/auth.log --enrich-all --out report.html
```

### Docker

```bash
docker pull sherlockholmes221b/authsentry:latest

docker run --rm \
  -v /var/log:/data/logs:ro \
  -v $(pwd)/output:/data/output \
  -e IPGEOLOCATION_API_KEY=your_key \
  sherlockholmes221b/authsentry \
  /data/logs/auth.log --enrich-all --out /data/output/report.html
```

---

## Getting an API Key

1. Go to [https://ipgeolocation.io](https://ipgeolocation.io) and sign up for a free account  
   → API docs: [IP Location](https://ipgeolocation.io/documentation/ip-location-api.html) · [IP Security](https://ipgeolocation.io/documentation/ip-security-api.html)
2. Copy your API key from the dashboard
3. Set it: `export IPGEOLOCATION_API_KEY=your_key` or pass `--api-key your_key`

The free tier includes 1,000 requests/day. The cache means you'll rarely hit this on repeat runs.

---

## Usage

```
authsentry [log-file] [flags]

Flags:
  --api-key string        IPGeolocation API key (or IPGEOLOCATION_API_KEY env var)
  --format string         Log format: auto, django, laravel, rails, apache, nginx, raw (default "auto")
  --output string         Output format: html, json (default "html")
  -o, --out string        Output file path (stdout for json, report.html for html)
  --workers int           Parallel enrichment workers (default 10)
  --rps float             Max API requests per second (default 10)
  --cache string          SQLite cache file (default "cache.db")
  --cache-ttl-hours int   Cache TTL in hours (default 24)
  --max-enrich int        Max IPs to enrich (0 = prompt)
  --enrich-all            Enrich all IPs without prompting
  --no-prompt             Non-interactive mode (for scripts/CI)
  --dedupe-cap int        In-memory dedup capacity (default 100000)
```

### Examples

```bash
# Auto-detect format, produce HTML report
./authsentry /var/log/nginx/access.log --out report.html --enrich-all

# Django log, JSON output, 20 workers, 25 RPS
./authsentry app.log --format django --output json --workers 20 --rps 25 --enrich-all

# Limit enrichment to first 500 unique IPs, then stop
./authsentry big.log --max-enrich 500 --out report.html

# Pipe JSON to jq for CRITICAL events only
./authsentry auth.log --output json --no-prompt | \
  jq '.events[] | select(.risk.level == "CRITICAL")'

# CI/CD pipeline - non-interactive, fail if any CRITICAL found
./authsentry auth.log --output json --enrich-all --no-prompt > results.json
jq -e '[.events[] | select(.risk.level == "CRITICAL")] | length == 0' results.json

# Reuse cache from previous run (much faster second run)
./authsentry new_auth.log --cache ./shared_cache.db --enrich-all --out report.html
```

---

## Supported Log Formats

### Django
```
2024-01-15 10:23:45,123 WARNING django.security Failed login for user 'admin' from 1.2.3.4
```

### Laravel
```
[2024-01-15 10:23:45] production.WARNING: Failed login {"ip":"1.2.3.4","email":"user@example.com"}
```

### Rails
```
Started POST "/users/sign_in" for 1.2.3.4 at 2024-01-15 10:23:45
```

### Apache / Nginx Combined Log
```
1.2.3.4 - admin [15/Jan/2024:10:23:45 +0000] "POST /login HTTP/1.1" 401 512
```

### Raw (fallback)
Any line containing login-related keywords with an extractable IP address.

---

## Risk Scoring

AuthSentry combines multiple signals to produce a verdict, powered by the [IP Location API](https://ipgeolocation.io/documentation/ip-location-api.html) and [IP Security API](https://ipgeolocation.io/documentation/ip-security-api.html):

| Signal | Points |
|---|---|
| Hosting/datacenter ASN type | +30 |
| VPN detected | +25 |
| Proxy detected | +20 |
| Tor exit node | +50 |
| Anonymizer/relay | +20 |
| Known attacker (from API) | +45 |
| Known abuser | +30 |
| Threat flag | +25 |
| API threat score ≥ 80 | +20 |
| API threat score 50–79 | +10 |
| Hosting + VPN combo (bonus) | +15 |
| Failed login from suspicious IP | +10 |

| Score | Level | Recommended Action |
|---|---|---|
| 75–100 | **CRITICAL** | Block IP immediately |
| 50–74 | **HIGH** | Challenge with MFA/CAPTCHA |
| 25–49 | **MEDIUM** | Log, monitor, alert account owner |
| 1–24 | **LOW** | Log for trend analysis |
| 0 | **INFO** | No action required |

---

## Docker

### Build locally
```bash
make docker
# or
docker build -t authsentry:latest .
```

### Run with docker compose
```bash
# Create your log and output directories
mkdir -p logs output

# Copy your log file
cp /var/log/auth.log logs/

# Run
IPGEOLOCATION_API_KEY=your_key docker compose run authsentry \
  /data/logs/auth.log --enrich-all --out /data/output/report.html
```

### Multi-arch build (for Docker Hub)
```bash
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t sherlockholmes221b/authsentry:latest \
  --push .
```

---

## Development

```bash
# Run tests
make test

# Run against sample data
make run-example

# Lint
make lint

# Clean
make clean
```

### Project Structure
```
authsentry/
├── main.go
├── cmd/
│   └── root.go           # CLI flags and orchestration
├── internal/
│   ├── parser/
│   │   └── parser.go     # Multi-format log parser (streaming)
│   ├── enricher/
│   │   ├── enricher.go   # ipgeolocation.io API client
│   │   └── scorer.go     # Risk scoring engine
│   ├── cache/
│   │   └── cache.go      # SQLite cache with TTL
│   ├── worker/
│   │   └── pool.go       # Parallel worker pool with dedup
│   ├── ratelimit/
│   │   └── limiter.go    # Token-bucket rate limiter
│   └── reporter/
│       ├── reporter.go   # HTML + JSON output
│       └── template.go   # HTML report template
├── testdata/
│   ├── sample_django.log
│   └── sample_apache.log
├── Dockerfile
├── docker-compose.yml
└── Makefile
```

---

## Step-by-Step: From Zero to Published

See [SETUP_GUIDE.md](SETUP_GUIDE.md) for the complete walkthrough: creating the GitHub repo, getting an API key, building, Docker Hub publishing, and CI/CD setup.

---

## License

MIT
