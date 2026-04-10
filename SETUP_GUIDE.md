# AuthSentry — Complete Setup Guide

This guide walks you from a blank machine to a published Docker image with CI/CD.

---

## Part 1: Prerequisites

### Install Go (1.22+)
```bash
# Linux
wget https://go.dev/dl/go1.22.4.linux-amd64.tar.gz
sudo tar -C /usr/local -xzf go1.22.4.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
source ~/.bashrc
go version  # should print go1.22.4

# macOS (Homebrew)
brew install go

# Windows
# Download installer from https://go.dev/dl/
```

### Install GCC (required for SQLite)
```bash
# Ubuntu/Debian
sudo apt install gcc libsqlite3-dev

# macOS (comes with Xcode CLT)
xcode-select --install

# Windows
# Install TDM-GCC from https://jmeubank.github.io/tdm-gcc/
```

### Install Docker
```bash
# Ubuntu
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# macOS / Windows
# Install Docker Desktop: https://www.docker.com/products/docker-desktop/
```

### Install Git
```bash
sudo apt install git         # Ubuntu
brew install git             # macOS
# Windows: https://git-scm.com/download/win
```

---

## Part 2: Get the ipgeolocation.io API Key

1. Go to **https://ipgeolocation.io** and click **Sign Up**
2. Create a free account (no credit card needed)
3. After login, go to **Dashboard → API Keys**
4. Click **Create Key**, name it `authsentry`
5. Copy the key — looks like: `iq_abc123xyz...`

Add it to your environment permanently:
```bash
# Linux/macOS — add to ~/.bashrc or ~/.zshrc
echo 'export IPGEOLOCATION_API_KEY=iq_your_key_here' >> ~/.bashrc
source ~/.bashrc

# Or use a .env file (never commit this)
echo 'IPGEOLOCATION_API_KEY=iq_your_key_here' > .env
```

---

## Part 3: Create the GitHub Repository

### Step 1 — Create the repo on GitHub
1. Go to **https://github.com/new**
2. Repository name: `authsentry`
3. Set to **Public** (required for free GitHub Actions minutes)
4. ✅ Add a README: **No** (we have our own)
5. Click **Create repository**

### Step 2 — Initialize locally
```bash
git clone https://github.com/devjfreaks/authsentry.git
cd authsentry

# Copy all project files here, then:
git add .
git commit -m "feat: initial implementation"
git push origin main
```

### Step 3 — Add repository secrets for CI/CD
Go to your repo → **Settings → Secrets and variables → Actions → New repository secret**

Add these secrets:
| Secret | Value |
|---|---|
| `DOCKERHUB_USERNAME` | Your Docker Hub username |
| `DOCKERHUB_TOKEN` | Docker Hub access token (see Part 5) |

---

## Part 4: Build & Run Locally

```bash
cd authsentry

# Build the binary (CGO_ENABLED=1 required for SQLite)
CGO_ENABLED=1 go build -o authsentry .

# Run against sample data (no API key needed)
./authsentry testdata/sample_django.log \
  --format django \
  --no-prompt \
  --out report.html

open report.html  # macOS
xdg-open report.html  # Linux

# Run with API key enrichment
export IPGEOLOCATION_API_KEY=your_key
./authsentry testdata/sample_django.log \
  --format django \
  --enrich-all \
  --workers 10 \
  --rps 10 \
  --out report.html

# Run tests
CGO_ENABLED=1 go test ./... -v
```

---

## Part 5: Docker Hub Setup

### Create a Docker Hub account
1. Go to **https://hub.docker.com** and sign up
2. Create a repository: **Repositories → Create Repository**
   - Name: `authsentry`
   - Visibility: Public
3. Create an access token: **Account Settings → Security → New Access Token**
   - Description: `authsentry-ci`
   - Permissions: Read, Write, Delete
   - Copy the token

### Build and push manually (first time)
```bash
# Login
docker login -u sherlockholmes221b

# Build
docker build -t sherlockholmes221b/authsentry:latest .

# Test the image
docker run --rm \
  -v $(pwd)/testdata:/data:ro \
  sherlockholmes221b/authsentry \
  /data/sample_django.log --format django --no-prompt --output json

# Push
docker push sherlockholmes221b/authsentry:latest
```

### Multi-architecture build (amd64 + arm64)
```bash
# One-time setup
docker buildx create --name multibuilder --use

# Build and push both architectures
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  -t sherlockholmes221b/authsentry:latest \
  --push .
```

---

## Part 6: Release a Version

### Tag a release
```bash
git tag v1.0.0
git push origin v1.0.0
```

This triggers the GitHub Actions CI workflow which will:
1. Run all tests
2. Build and push Docker images tagged `v1.0.0`, `1.0`, and `latest`
3. Cross-compile binaries for Linux (amd64), macOS (amd64/arm64)
4. Create a GitHub Release with binary downloads and checksums

---

## Part 7: CI/CD Walkthrough

The workflow file is at `.github/workflows/ci.yml`. Here's what happens on each event:

### On every push / PR
- Sets up Go 1.22
- Installs `libsqlite3-dev`
- Runs `go test ./... -race`
- Builds the binary

### On push to `main`
- All of the above
- Builds Docker image and pushes to GHCR (GitHub Container Registry) as `ghcr.io/devjfreaks/authsentry:latest`
- Also pushes to Docker Hub if `DOCKERHUB_USERNAME` secret is set

### On version tag (`v*`)
- All of the above
- Builds release binaries for Linux/macOS
- Creates SHA256 checksums
- Creates a GitHub Release with binaries attached

---

## Part 8: Using in Production

### Cron job — nightly report
```bash
# /etc/cron.d/authsentry
0 1 * * * root /usr/local/bin/authsentry \
  /var/log/nginx/access.log \
  --enrich-all \
  --no-prompt \
  --workers 20 \
  --rps 15 \
  --cache /var/cache/authsentry/cache.db \
  --out /var/reports/auth-$(date +\%Y\%m\%d).html \
  2>> /var/log/authsentry.log
```

### Kubernetes CronJob
```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: authsentry
spec:
  schedule: "0 1 * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: authsentry
            image: sherlockholmes221b/authsentry:latest
            args:
              - /data/logs/access.log
              - --enrich-all
              - --no-prompt
              - --out
              - /data/reports/report.html
            env:
            - name: IPGEOLOCATION_API_KEY
              valueFrom:
                secretKeyRef:
                  name: authsentry-secrets
                  key: api-key
            volumeMounts:
            - name: logs
              mountPath: /data/logs
            - name: reports
              mountPath: /data/reports
            - name: cache
              mountPath: /data/cache
          restartPolicy: OnFailure
```

### CI/CD gate — fail build on critical logins
```yaml
# In your existing CI pipeline
- name: Analyze auth logs
  run: |
    ./authsentry auth.log --output json --enrich-all --no-prompt > results.json
    CRITICAL=$(jq '[.events[] | select(.risk.level == "CRITICAL")] | length' results.json)
    if [ "$CRITICAL" -gt "0" ]; then
      echo "::error::$CRITICAL CRITICAL risk login events detected!"
      jq '.events[] | select(.risk.level == "CRITICAL") | {ip, timestamp: .timestamp, reasons: .risk.reasons}' results.json
      exit 1
    fi
```

---

## Part 9: Updating & Maintenance

### Update the binary
```bash
git pull
CGO_ENABLED=1 go build -o authsentry .
```

### Purge stale cache entries
The cache auto-expires entries older than `--cache-ttl-hours`, but you can also purge manually:
```bash
sqlite3 cache.db "DELETE FROM ip_cache WHERE cached_at < strftime('%s', 'now') - 86400;"
```

### Check cache stats
```bash
sqlite3 cache.db "SELECT COUNT(*) as cached_ips, datetime(MIN(cached_at), 'unixepoch') as oldest FROM ip_cache;"
```

---

## Troubleshooting

| Problem | Fix |
|---|---|
| `CGO_ENABLED` error | Install `gcc` and `libsqlite3-dev` |
| `rate limited by API` | Lower `--rps` or upgrade ipgeolocation.io plan |
| No events parsed | Check `--format` flag matches your log type |
| Empty report | Log lines may not match login patterns — try `--format raw` |
| Docker `permission denied` | Mount volumes as correct user or use `--user $(id -u)` |
| Cache not helping | Ensure `--cache` points to same file across runs |
