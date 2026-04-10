package agent

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/seanmatheny/coldcrypt/internal/config"
	"github.com/seanmatheny/coldcrypt/internal/db"
	"github.com/seanmatheny/coldcrypt/internal/transfer"
)

// ErrAlreadyRunning is returned by Run when a backup job is already in progress.
var ErrAlreadyRunning = errors.New("a backup job is already in progress")

// BackupOptions configures a single backup run.
type BackupOptions struct {
	SourceDirs   []string
	ExcludePaths []string
	JobID        int64
}

// Agent performs backup and restore operations.
type Agent struct {
	cfg     *config.Config
	db      *db.DB
	key     []byte
	running int32 // atomic: 1 while a backup job is running
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

// IsRunning reports whether a backup job is currently in progress.
func (a *Agent) IsRunning() bool {
	return atomic.LoadInt32(&a.running) == 1
}

// Run performs a full incremental backup.
func (a *Agent) Run(ctx context.Context, opts BackupOptions) error {
	if !atomic.CompareAndSwapInt32(&a.running, 0, 1) {
		return ErrAlreadyRunning
	}
	defer atomic.StoreInt32(&a.running, 0)

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
				if isExcluded(path, opts.ExcludePaths) {
					return filepath.SkipDir
				}
				return nil
			}
			if isExcluded(path, opts.ExcludePaths) {
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

			// Generate blob ID (UUID).
			blobID := uuid.New().String()

			// Encrypt and upload via a pipe so the plaintext allocation can be
			// reclaimed by the GC while the upload is in progress, instead of
			// buffering a third full copy in a bytes.Buffer.
			pr, pw := io.Pipe()
			encErrCh := make(chan error, 1)
			go func() {
				err := EncryptFile(a.key, f, pw)
				pw.CloseWithError(err)
				encErrCh <- err
			}()

			uploadErr := client.UploadBlob(a.cfg.RemoteBasePath, blobID, pr)
			if uploadErr != nil {
				// Unblock the encrypt goroutine if it is blocked writing to the pipe.
				_ = pr.CloseWithError(uploadErr)
			} else {
				_ = pr.Close()
			}
			encErr := <-encErrCh

			if uploadErr != nil {
				log.Printf("upload error %s: %v", path, uploadErr)
				return nil
			}
			if encErr != nil {
				log.Printf("encrypt error %s: %v", path, encErr)
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

// isExcluded reports whether path matches any of the given exclude paths.
// A path is excluded if it equals an exclude entry or is nested under one.
func isExcluded(path string, excludePaths []string) bool {
	cleanPath := filepath.Clean(path)
	for _, excl := range excludePaths {
		if excl == "" {
			continue
		}
		cleanExcl := filepath.Clean(excl)
		if cleanPath == cleanExcl || strings.HasPrefix(cleanPath, cleanExcl+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}
