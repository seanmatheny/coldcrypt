# Coldcrypt 🔒

A client-side encrypted backup manager with a web GUI, SCP transfer, and automatic file versioning.

---

## Features

- **Client-side AES-256-GCM encryption** — files are encrypted before leaving your machine; the remote server never sees plaintext or keys
- **Argon2id key derivation** — strong, memory-hard KDF (time=1, memory=64 MiB, threads=4)
- **SCP transfer** — encrypted blobs uploaded over SSH/SCP
- **File versioning** — up to 3 versions per file; when a 4th is written the oldest is automatically evicted from both DB and remote
- **Incremental backups** — SHA-256 content hashing skips unchanged files
- **Cron scheduler** — define recurring backup schedules via the web UI
- **Password-protected web UI** — dark-themed SPA for managing files, jobs, schedules, and settings
- **Purge** — permanently delete backed-up blobs for a specific directory prefix or the entire backup, from both the CLI and the web UI

---

## Architecture

```
coldcrypt/
├── cmd/coldcrypt/main.go          CLI entry point
├── internal/
│   ├── config/config.go           JSON config load/save
│   ├── db/db.go                   SQLite (pure-Go, no CGO)
│   ├── agent/
│   │   ├── encrypt.go             AES-256-GCM + Argon2id
│   │   ├── agent.go               Backup logic (walk → hash → encrypt → upload)
│   │   └── restore.go             Download + decrypt to local path
│   ├── transfer/scp.go           SSH/SCP client
│   ├── scheduler/scheduler.go     Cron-based scheduler
│   └── web/
│       ├── auth.go                Session store (24h TTL, crypto/rand IDs)
│       ├── handlers.go            REST API handlers
│       ├── server.go              HTTP(S) server with embedded static files
│       └── static/                SPA (Bootstrap 5 + vanilla JS)
└── go.mod
```

### How encryption works

1. On first `init`, a random 32-byte salt is generated and stored in `config.json` (base64).
2. At startup, `Argon2id(passphrase, salt)` derives a 32-byte AES key — **the key never leaves the process**.
3. Each file is encrypted with `AES-256-GCM`:
   - A fresh 12-byte nonce is generated per file per backup.
   - Output blob format: `[12-byte nonce][ciphertext+16-byte GCM tag]`
4. The blob is uploaded to the remote SCP server using a UUID filename.
5. The remote server stores only opaque encrypted blobs — no filenames, no keys.

### Versioning strategy

- The DB stores up to **3 versions** per source path.
- When a 4th version is created, the version with the oldest `encrypted_at` timestamp is evicted.
- Its blob ID is returned to the backup agent, which deletes it from the remote server.
- Version numbers are monotonically increasing (not reset on eviction).

---

## Installation

Requires Go 1.22+:

```bash
git clone https://github.com/seanmatheny/coldcrypt
cd coldcrypt
go build ./cmd/coldcrypt/
# Binary: ./coldcrypt
```

---

## Quick Start

### 1. Initialize a data directory

```bash
./coldcrypt init ~/.coldcrypt
```

This creates `~/.coldcrypt/config.json` with a pre-generated key salt and template values.

### 2. Edit the config

```bash
$EDITOR ~/.coldcrypt/config.json
```

At minimum set:
- `remote_host`, `remote_user`, `remote_key_path`
- `source_dirs` — list of directories to back up
- `passphrase` — replace the placeholder with a strong passphrase (or use `passphrase_file`)
- `data_dir` — should match the directory you initialized

### 3. Set the web UI password

```bash
./coldcrypt change-password --config ~/.coldcrypt/config.json
```

### 4. Start the server

```bash
./coldcrypt serve --config ~/.coldcrypt/config.json
# Open https://localhost:8443
```

---

## Configuration Reference

| Key | Default | Description |
|-----|---------|-------------|
| `remote_host` | — | SCP server hostname/IP |
| `remote_port` | `22` | SCP server port |
| `remote_user` | — | SSH username |
| `remote_key_path` | — | Path to SSH private key |
| `remote_password` | — | SSH password (if not using key) |
| `remote_base_path` | `/backup/coldcrypt` | Base directory on remote server |
| `source_dirs` | `[]` | Directories to back up |
| `passphrase` | — | Encryption passphrase (inline) |
| `passphrase_file` | — | Path to file containing passphrase |
| `web_port` | `8443` | Web UI port |
| `web_password_hash` | — | bcrypt hash of web UI password |
| `web_tls_cert` | — | Path to TLS certificate (enables HTTPS) |
| `web_tls_key` | — | Path to TLS private key |
| `data_dir` | — | Directory for SQLite DB and config |
| `key_salt` | — | Base64 Argon2id salt (auto-generated on init) |

---

## CLI Commands

```
coldcrypt init <data-dir>
    Create data directory, generate key salt, write template config.

coldcrypt serve [--config path]
    Start the web server and cron scheduler.
    Searches for config.json in: ./config.json, ~/.coldcrypt/config.json, /etc/coldcrypt/config.json

coldcrypt backup [--config path] [dir1 dir2 ...]
    Run a one-off backup. Uses source_dirs from config if no dirs specified.

coldcrypt purge [--config path] [--path <display-prefix>] [--yes]
    Permanently delete backed-up blobs from the remote server and clear matching
    database records. Without --path, ALL backups are purged. With --path, only
    files whose display path starts with the given prefix are purged.
    Requires typing DELETE ALL at the confirmation prompt unless --yes is given.

coldcrypt db-dump --out <file> [--config path]
    Create a consistent copy of the SQLite database at the given path.
    Safe to run while the server is running (uses SQLite VACUUM INTO).
    Ideal for crontab-based database backups — see examples below.

coldcrypt change-password [--config path]
    Interactively set the web UI password (uses bcrypt).
```

### Database backups

Coldcrypt stores all file metadata (hashes, blob IDs, job history, schedules) in a
single SQLite file at `<data_dir>/coldcrypt.db`. It is a good idea to back this file
up independently of your encrypted blobs.

The `db-dump` command creates a clean, consistent snapshot using SQLite's
`VACUUM INTO` — it is safe to run while `coldcrypt serve` is running.

**Manual dump:**
```bash
coldcrypt db-dump --config /etc/coldcrypt/config.json \
                  --out ~/coldcrypt-$(date +%Y%m%d).db
```

**Daily crontab entry** (runs at 03:00, keeps 30 days of dumps):
```bash
sudo mkdir -p /var/lib/coldcrypt
sudo chown -R coldcrypt:coldcrypt /var/lib/coldcrypt
```

```cron
0 3 * * * /usr/local/bin/coldcrypt db-dump \
              --config /etc/coldcrypt/config.json \
              --out /var/lib/coldcrypt-$(date +%Y%m%d).db && \
          find /backup -name 'coldcrypt-*.db' -mtime +30 -delete
```

---

## Web UI Guide

After signing in at `http(s)://localhost:8443`:

- **Dashboard** — overview stats, recent jobs, "Run Backup Now" button
- **Files** — searchable pseudo-filesystem browser; click "Versions" on any file to see its backup history and trigger a restore; click "Restore" on a directory to restore all its files; click "Purge" on a directory (or "Purge All" in the header) to permanently delete its backed-up blobs
- **Jobs** — full backup job history with status badges (green=completed, yellow=running, red=failed); auto-refreshes for running jobs
- **Schedules** — add/edit/delete cron-based schedules; examples provided for common intervals
- **Settings** — edit remote server config, source directories, and change the web UI password

---

## Running as a systemd service

A ready-made unit file is provided in `contrib/coldcrypt.service`.

### 1. Install the binary

```bash
go build ./cmd/coldcrypt/
sudo install -o root -g root -m 755 coldcrypt /usr/local/bin/coldcrypt
```

### 2. Create a dedicated user and directories

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin coldcrypt

# Config and data in /etc/coldcrypt and /var/lib/coldcrypt (adjust to taste).
# The data and log directories (/var/lib/coldcrypt, /var/log/coldcrypt) are
# created automatically by systemd when the service unit is installed thanks to
# StateDirectory= and LogsDirectory=.  You only need to create the config dir
# and initialise coldcrypt here.
sudo mkdir -p /etc/coldcrypt
sudo coldcrypt init /var/lib/coldcrypt
sudo cp /var/lib/coldcrypt/config.json /etc/coldcrypt/config.json
# Edit /etc/coldcrypt/config.json — set data_dir to /var/lib/coldcrypt
sudo chown -R coldcrypt:coldcrypt /etc/coldcrypt
sudo chmod 700 /etc/coldcrypt
```

### 3. Set the web UI password

```bash
sudo -u coldcrypt coldcrypt change-password --config /etc/coldcrypt/config.json
```

### 4. Install and enable the unit

```bash
sudo cp contrib/coldcrypt.service /etc/systemd/system/coldcrypt.service

# If your source directories are outside /home or /srv/data, uncomment and
# edit the ReadOnlyPaths= line in the unit file first. If you want to restore
# files into directories outside /var/lib/coldcrypt or /var/log/coldcrypt,
# add them to ReadWritePaths= as well. With ProtectSystem=strict enabled,
# directories like /Restore are read-only to the service unless explicitly
# whitelisted.

sudo systemctl daemon-reload
sudo systemctl enable --now coldcrypt
# systemd creates /var/lib/coldcrypt and /var/log/coldcrypt (owned by the
# coldcrypt user) automatically on first start via StateDirectory= and
# LogsDirectory= in the unit file.
sudo systemctl status coldcrypt
```

Example unit overrides:

```ini
# Allow reading additional backup source directories.
ReadOnlyPaths=/home /srv/data

# Allow restoring into custom writable destinations.
ReadWritePaths=/Restore /mnt/restore-target
```

### 5. View logs

```bash
# systemd journal (primary log destination)
sudo journalctl -u coldcrypt -f

# File log written by the service (created automatically under LogsDirectory=)
sudo tail -f /var/log/coldcrypt/coldcrypt.log
```

---

## Security Notes

- **Argon2id parameters**: time=1, memory=64 MiB, threads=4, output=32 bytes. These are conservative; increase `time` for higher security at the cost of startup latency.
- **AES-256-GCM** provides both confidentiality and integrity. Any tampering with a blob will cause decryption to fail.
- **No keys on remote**: the SCP server stores only opaque UUID-named blobs. Compromise of the remote server does not expose plaintext.
- **Passphrase security**: use a long, random passphrase. Store it in a `passphrase_file` with mode `0600` rather than inline in `config.json`.
- **TLS**: configure `web_tls_cert`/`web_tls_key` to enable HTTPS for the web UI.
- **Sessions**: web UI sessions expire after 24 hours and use 32-byte cryptographically random IDs.
- The SSH `HostKeyCallback` is set to `InsecureIgnoreHostKey` — for production use, replace with a known-hosts-based callback.
....
