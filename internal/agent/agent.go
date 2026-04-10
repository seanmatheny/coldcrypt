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
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/seanmatheny/coldcrypt/internal/config"
	"github.com/seanmatheny/coldcrypt/internal/db"
	"github.com/seanmatheny/coldcrypt/internal/transfer"
)

// ErrAlreadyRunning is returned by Run when a backup job is already in progress.
var ErrAlreadyRunning = errors.New("a backup job is already in progress")

// uploadWorkers is the number of concurrent encrypt-and-upload goroutines.
const uploadWorkers = 4

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

// fileWork is a single file to be processed by the worker pool.
type fileWork struct {
	path   string
	srcDir string
}

// Run performs a full incremental backup.
func (a *Agent) Run(ctx context.Context, opts BackupOptions) error {
	if !atomic.CompareAndSwapInt32(&a.running, 0, 1) {
		return ErrAlreadyRunning
	}
	defer atomic.StoreInt32(&a.running, 0)

	// Use a short-lived connection for the one-time EnsureDir metadata op.
	metaClient, err := transfer.NewClient(
		a.cfg.RemoteHost,
		a.cfg.RemotePort,
		a.cfg.RemoteUser,
		a.cfg.RemoteKeyPath,
		a.cfg.RemotePassword,
	)
	if err != nil {
		return fmt.Errorf("ssh connect: %w", err)
	}
	if err := metaClient.EnsureDir(a.cfg.RemoteBasePath); err != nil {
		metaClient.Close()
		return fmt.Errorf("ensure remote dir: %w", err)
	}
	metaClient.Close()

	var (
		mu               sync.Mutex
		filesProcessed   int
		bytesTransferred int64
	)

	workCh := make(chan fileWork, 64)

	var wg sync.WaitGroup
	for i := 0; i < uploadWorkers; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			// Each worker opens its own SSH connection so all four can
			// saturate their full share of the available bandwidth
			// simultaneously (one shared connection would serialize on
			// the single TCP congestion window).
			workerClient, err := transfer.NewClient(
				a.cfg.RemoteHost,
				a.cfg.RemotePort,
				a.cfg.RemoteUser,
				a.cfg.RemoteKeyPath,
				a.cfg.RemotePassword,
			)
			if err != nil {
				log.Printf("worker %d: connect error: %v", workerID, err)
				return
			}
			defer workerClient.Close()
			for item := range workCh {
				n, b := a.processFile(ctx, workerClient, opts, item.path, item.srcDir)
				if n > 0 {
					mu.Lock()
					filesProcessed += n
					bytesTransferred += b
					mu.Unlock()
				}
			}
		}(i)
	}

	for _, srcDir := range opts.SourceDirs {
		if ctx.Err() != nil {
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
			select {
			case workCh <- fileWork{path: path, srcDir: srcDir}:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})

		if walkErr != nil && !errors.Is(walkErr, context.Canceled) {
			log.Printf("walk error in %s: %v", srcDir, walkErr)
		}
	}

	close(workCh)
	wg.Wait()

	// Update job stats.
	_ = a.db.UpdateJob(opts.JobID, "completed", filesProcessed, bytesTransferred, "")
	log.Printf("backup job %d completed: %d files, %d bytes", opts.JobID, filesProcessed, bytesTransferred)
	return nil
}

// processFile checks whether a file needs backing up, and if so encrypts and
// uploads it. It returns (1, fileSize) when the file was backed up, otherwise
// (0, 0).
func (a *Agent) processFile(ctx context.Context, client *transfer.Client, opts BackupOptions, path, srcDir string) (int, int64) {
	if ctx.Err() != nil {
		return 0, 0
	}

	// Fast stat-based pre-check: skip the SHA-256 read if size and mtime are
	// identical to the last backed-up version.
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("stat error %s: %v", path, err)
		return 0, 0
	}
	currSize := info.Size()
	currMtimeNS := info.ModTime().UnixNano()

	storedHash, storedSize, storedMtimeNS, err := a.db.GetLatestVersionInfo(path)
	if err != nil {
		log.Printf("db info check error %s: %v", path, err)
		return 0, 0
	}
	if storedHash != "" && currSize == storedSize && currMtimeNS == storedMtimeNS {
		// Stat (size + mtime) is identical to the last backed-up version.
		// This is the same heuristic used by rsync and most backup tools: a
		// matching size+mtime almost always means unchanged content. Files
		// where the mtime is deliberately reset after modification (e.g. via
		// touch -t) will be missed until the next hash-verification run.
		return 0, 0
	}

	// Stat changed (or no prior version); verify content with SHA-256.
	hash, err := HashFile(path)
	if err != nil {
		log.Printf("hash error %s: %v", path, err)
		return 0, 0
	}
	if storedHash == hash {
		// Content unchanged despite stat difference (e.g. mtime was reset).
		// Update the stored mtime so future runs skip the hash computation.
		if err := a.db.UpdateLatestVersionMtime(path, currMtimeNS); err != nil {
			log.Printf("update mtime error %s: %v", path, err)
		}
		return 0, 0
	}

	// Content changed; encrypt and upload.
	f, err := os.Open(path)
	if err != nil {
		log.Printf("open error %s: %v", path, err)
		return 0, 0
	}
	defer f.Close()

	blobID := uuid.New().String()

	pr, pw := io.Pipe()
	encErrCh := make(chan error, 1)
	go func() {
		err := EncryptFile(a.key, f, pw)
		pw.CloseWithError(err)
		encErrCh <- err
	}()

	uploadErr := client.UploadBlob(a.cfg.RemoteBasePath, blobID, pr)
	if uploadErr != nil {
		_ = pr.CloseWithError(uploadErr)
	} else {
		_ = pr.Close()
	}
	encErr := <-encErrCh

	if uploadErr != nil {
		log.Printf("upload error %s: %v", path, uploadErr)
		return 0, 0
	}
	if encErr != nil {
		log.Printf("encrypt error %s: %v", path, encErr)
		return 0, 0
	}

	// Build display path relative to source dir.
	displayPath := path
	if rel, err := filepath.Rel(srcDir, path); err == nil {
		displayPath = filepath.Join(filepath.Base(srcDir), rel)
	}
	displayPath = strings.ReplaceAll(displayPath, string(os.PathSeparator), "/")

	// Store version in DB.
	oldBlobID, err := a.db.UpsertFileVersion(path, displayPath, blobID, hash, currSize, currMtimeNS, opts.JobID)
	if err != nil {
		log.Printf("db upsert error %s: %v", path, err)
		return 0, 0
	}

	// Delete evicted blob from remote if any.
	if oldBlobID != "" {
		if err := client.DeleteBlob(a.cfg.RemoteBasePath, oldBlobID); err != nil {
			log.Printf("delete old blob error %s: %v", oldBlobID, err)
		}
	}

	log.Printf("backed up: %s -> %s", path, blobID)
	return 1, currSize
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
