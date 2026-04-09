package agent

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/uuid"
	"github.com/seanmatheny/coldcrypt/internal/config"
	"github.com/seanmatheny/coldcrypt/internal/db"
	"github.com/seanmatheny/coldcrypt/internal/transfer"
)

// BackupOptions configures a single backup run.
type BackupOptions struct {
	SourceDirs []string
	JobID      int64
}

// Agent performs backup and restore operations.
type Agent struct {
	cfg *config.Config
	db  *db.DB
	key []byte
}

// New creates a new Agent, deriving the encryption key from the configured passphrase.
func New(cfg *config.Config, database *db.DB) (*Agent, error) {
	passphrase, err := cfg.GetPassphrase()
	if err != nil {
		return nil, fmt.Errorf("get passphrase: %w", err)
	}

	saltB64 := cfg.KeySalt
	if saltB64 == "" {
		return nil, fmt.Errorf("key_salt not set in config; run 'coldcrypt init' to generate one")
	}
	salt, err := base64.StdEncoding.DecodeString(saltB64)
	if err != nil {
		return nil, fmt.Errorf("decode key_salt: %w", err)
	}

	key := DeriveKey(passphrase, salt)
	return &Agent{cfg: cfg, db: database, key: key}, nil
}

// Run performs a full incremental backup.
func (a *Agent) Run(ctx context.Context, opts BackupOptions) error {
	client, err := transfer.NewClient(
		a.cfg.RemoteHost,
		a.cfg.RemotePort,
		a.cfg.RemoteUser,
		a.cfg.RemoteKeyPath,
		a.cfg.RemotePassword,
	)
	if err != nil {
		return fmt.Errorf("sftp connect: %w", err)
	}
	defer client.Close()

	if err := client.EnsureDir(a.cfg.RemoteBasePath); err != nil {
		return fmt.Errorf("ensure remote dir: %w", err)
	}

	var filesProcessed int
	var bytesTransferred int64

	for _, srcDir := range opts.SourceDirs {
		if err := ctx.Err(); err != nil {
			break
		}

		walkErr := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				log.Printf("walk error at %s: %v", path, err)
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if err := ctx.Err(); err != nil {
				return err
			}

			// Compute hash for incremental check.
			hash, err := HashFile(path)
			if err != nil {
				log.Printf("hash error %s: %v", path, err)
				return nil
			}

			latestHash, err := a.db.GetLatestVersionHash(path)
			if err != nil {
				log.Printf("db hash check error %s: %v", path, err)
				return nil
			}
			if latestHash == hash {
				// File unchanged; skip.
				return nil
			}

			// Read and encrypt file.
			f, err := os.Open(path)
			if err != nil {
				log.Printf("open error %s: %v", path, err)
				return nil
			}
			defer f.Close()

			fi, err := f.Stat()
			if err != nil {
				log.Printf("stat error %s: %v", path, err)
				return nil
			}
			fileSize := fi.Size()

			var encBuf bytes.Buffer
			if err := EncryptFile(a.key, f, &encBuf); err != nil {
				log.Printf("encrypt error %s: %v", path, err)
				return nil
			}

			// Generate blob ID (UUID).
			blobID := uuid.New().String()

			// Upload to remote.
			if err := client.UploadBlob(a.cfg.RemoteBasePath, blobID, &encBuf); err != nil {
				log.Printf("upload error %s: %v", path, err)
				return nil
			}

			// Build display path relative to source dir.
			displayPath := path
			if rel, err := filepath.Rel(srcDir, path); err == nil {
				displayPath = filepath.Join(filepath.Base(srcDir), rel)
			}
			// Normalize to forward slashes.
			displayPath = strings.ReplaceAll(displayPath, string(os.PathSeparator), "/")

			// Store version in DB.
			oldBlobID, err := a.db.UpsertFileVersion(path, displayPath, blobID, hash, fileSize, opts.JobID)
			if err != nil {
				log.Printf("db upsert error %s: %v", path, err)
				return nil
			}

			// Delete evicted blob from remote if any.
			if oldBlobID != "" {
				if err := client.DeleteBlob(a.cfg.RemoteBasePath, oldBlobID); err != nil {
					log.Printf("delete old blob error %s: %v", oldBlobID, err)
				}
			}

			filesProcessed++
			bytesTransferred += fileSize
			log.Printf("backed up: %s -> %s", path, blobID)
			return nil
		})

		if walkErr != nil && walkErr != context.Canceled {
			log.Printf("walk error in %s: %v", srcDir, walkErr)
		}
	}

	// Update job stats.
	_ = a.db.UpdateJob(opts.JobID, "completed", filesProcessed, bytesTransferred, "")
	log.Printf("backup job %d completed: %d files, %d bytes", opts.JobID, filesProcessed, bytesTransferred)
	return nil
}
