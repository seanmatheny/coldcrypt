# Coldcrypt 🔒

A client-side encrypted backup manager with a web GUI, SFTP transfer, and automatic file versioning.

---

## Features

- **Client-side AES-256-GCM encryption** — files are encrypted before leaving your machine; the remote server never sees plaintext or keys
- **Argon2id key derivation** — strong, memory-hard KDF (time=1, memory=64 MiB, threads=4)
- **SFTP transfer** — encrypted blobs uploaded over SSH/SFTP
- **File versioning** — up to 3 versions per file; when a 4th is written the oldest is automatically evicted from both DB and remote
- **Incremental backups** — SHA-256 content hashing skips unchanged files
- **Cron scheduler** — define recurring backup schedules via the web UI
- **Password-protected web UI** — dark-themed SPA for managing files, jobs, schedules, and settings

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
│   ├── transfer/sftp.go           SSH/SFTP client
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
4. The blob is uploaded to the remote SFTP server using a UUID filename.
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
| `remote_host` | — | SFTP server hostname/IP |
| `remote_port` | `22` | SFTP server port |
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

coldcrypt change-password [--config path]
    Interactively set the web UI password (uses bcrypt).
```

---

## Web UI Guide

After signing in at `http(s)://localhost:8443`:

- **Dashboard** — overview stats, recent jobs, "Run Backup Now" button
- **Files** — searchable pseudo-filesystem browser; click "Versions" on any file to see its backup history and trigger a restore
- **Jobs** — full backup job history with status badges (green=completed, yellow=running, red=failed); auto-refreshes for running jobs
- **Schedules** — add/edit/delete cron-based schedules; examples provided for common intervals
- **Settings** — edit remote server config, source directories, and change the web UI password

---

## Security Notes

- **Argon2id parameters**: time=1, memory=64 MiB, threads=4, output=32 bytes. These are conservative; increase `time` for higher security at the cost of startup latency.
- **AES-256-GCM** provides both confidentiality and integrity. Any tampering with a blob will cause decryption to fail.
- **No keys on remote**: the SFTP server stores only opaque UUID-named blobs. Compromise of the remote server does not expose plaintext.
- **Passphrase security**: use a long, random passphrase. Store it in a `passphrase_file` with mode `0600` rather than inline in `config.json`.
- **TLS**: configure `web_tls_cert`/`web_tls_key` to enable HTTPS for the web UI.
- **Sessions**: web UI sessions expire after 24 hours and use 32-byte cryptographically random IDs.
- The SSH `HostKeyCallback` is set to `InsecureIgnoreHostKey` — for production use, replace with a known-hosts-based callback.
