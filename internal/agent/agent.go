package agent

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/seanmatheny/coldcrypt/internal/config"
	"github.com/seanmatheny/coldcrypt/internal/db"
	"github.com/seanmatheny/coldcrypt/internal/notify"
	"github.com/seanmatheny/coldcrypt/internal/transfer"
)

// ErrAlreadyRunning is returned by Run when a backup job is already in progress.
var ErrAlreadyRunning = errors.New("a backup job is already in progress")

// ErrRestoreAlreadyRunning is returned when a restore job is already in progress.
var ErrRestoreAlreadyRunning = errors.New("a restore job is already in progress")

// ErrScanAlreadyRunning is returned when an integrity scan is already in progress.
var ErrScanAlreadyRunning = errors.New("an integrity scan is already in progress")

// uploadWorkers is the number of concurrent encrypt-and-upload goroutines.
const uploadWorkers = 4

// BackupOptions configures a single backup run.
type BackupOptions struct {
	SourceDirs     []string
	ExcludePaths   []string
	ExcludeRegexes []string
	JobID          int64
}

// Agent performs backup and restore operations.
type Agent struct {
	cfg     *config.Config
	db      *db.DB
	key     []byte
	running int32 // atomic: 1 while a backup job is running

	restoreRunning int32 // atomic: 1 while a restore job is running
	scanRunning    int32 // atomic: 1 while an integrity scan is running

	// mu guards cancelFn, currentFile, jobID, and jobStart.
	mu          sync.RWMutex
	cancelFn    context.CancelFunc
	currentFile string
	jobID       int64
	jobStart    time.Time

	// Atomic live counters, reset at job start.
	filesProc int64
	bytesXfer int64

	// Atomic live counters for restore jobs, reset at restore start.
	restoreFilesProc int64
	restoreBytesXfer int64
	scanFilesProc    int64
	scanTotal        int64

	// Restore job metadata (guarded by mu).
	restoreCurrentFile string
	restoreJobID       int64
	restoreJobStart    time.Time

	// Scan job metadata (guarded by mu).
	scanCancelFn    context.CancelFunc
	scanCurrentFile string
	scanJobID       int64
	scanJobStart    time.Time
}

// AgentStatus holds a snapshot of the agent's current state for the live UI.
type AgentStatus struct {
	Running          bool
	JobType          string
	JobID            int64
	CurrentFile      string
	FilesProcessed   int64
	TotalFiles       int64
	BytesTransferred int64
	StartedAt        time.Time
}

// GetStatus returns a consistent snapshot of the agent's current state.
func (a *Agent) GetStatus() AgentStatus {
	a.mu.RLock()
	cf := a.currentFile
	jid := a.jobID
	jstart := a.jobStart
	a.mu.RUnlock()
	return AgentStatus{
		Running:          atomic.LoadInt32(&a.running) == 1,
		JobType:          "backup",
		JobID:            jid,
		CurrentFile:      cf,
		FilesProcessed:   atomic.LoadInt64(&a.filesProc),
		TotalFiles:       0,
		BytesTransferred: atomic.LoadInt64(&a.bytesXfer),
		StartedAt:        jstart,
	}
}

// GetRestoreStatus returns a consistent snapshot of the current restore job.
func (a *Agent) GetRestoreStatus() AgentStatus {
	a.mu.RLock()
	cf := a.restoreCurrentFile
	jid := a.restoreJobID
	jstart := a.restoreJobStart
	a.mu.RUnlock()
	return AgentStatus{
		Running:          atomic.LoadInt32(&a.restoreRunning) == 1,
		JobType:          "restore",
		JobID:            jid,
		CurrentFile:      cf,
		FilesProcessed:   atomic.LoadInt64(&a.restoreFilesProc),
		TotalFiles:       0,
		BytesTransferred: atomic.LoadInt64(&a.restoreBytesXfer),
		StartedAt:        jstart,
	}
}

// Stop cancels the currently running backup job. Returns true if a job was running.
func (a *Agent) Stop() bool {
	a.mu.RLock()
	fn := a.cancelFn
	a.mu.RUnlock()
	if fn != nil {
		fn()
		return true
	}
	return false
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

// IsRestoreRunning reports whether a restore job is currently in progress.
func (a *Agent) IsRestoreRunning() bool {
	return atomic.LoadInt32(&a.restoreRunning) == 1
}

// IsScanRunning reports whether an integrity scan is currently in progress.
func (a *Agent) IsScanRunning() bool {
	return atomic.LoadInt32(&a.scanRunning) == 1
}

// StopScan cancels the currently running scan job.
func (a *Agent) StopScan() bool {
	a.mu.RLock()
	fn := a.scanCancelFn
	a.mu.RUnlock()
	if fn != nil {
		fn()
		return true
	}
	return false
}

// GetScanStatus returns a consistent snapshot of the current scan job.
func (a *Agent) GetScanStatus() AgentStatus {
	a.mu.RLock()
	cf := a.scanCurrentFile
	jid := a.scanJobID
	jstart := a.scanJobStart
	a.mu.RUnlock()
	return AgentStatus{
		Running:          atomic.LoadInt32(&a.scanRunning) == 1,
		JobType:          "scan",
		JobID:            jid,
		CurrentFile:      cf,
		FilesProcessed:   atomic.LoadInt64(&a.scanFilesProc),
		TotalFiles:       atomic.LoadInt64(&a.scanTotal),
		BytesTransferred: 0,
		StartedAt:        jstart,
	}
}

func (a *Agent) startRestore(jobID int64) error {
	if !atomic.CompareAndSwapInt32(&a.restoreRunning, 0, 1) {
		return ErrRestoreAlreadyRunning
	}
	a.mu.Lock()
	a.restoreJobID = jobID
	a.restoreJobStart = time.Now()
	a.restoreCurrentFile = ""
	a.mu.Unlock()
	atomic.StoreInt64(&a.restoreFilesProc, 0)
	atomic.StoreInt64(&a.restoreBytesXfer, 0)
	return nil
}

func (a *Agent) finishRestore() {
	atomic.StoreInt32(&a.restoreRunning, 0)
	a.mu.Lock()
	a.restoreCurrentFile = ""
	a.restoreJobID = 0
	a.restoreJobStart = time.Time{}
	a.mu.Unlock()
}

func (a *Agent) setRestoreCurrentFile(path string) {
	a.mu.Lock()
	a.restoreCurrentFile = path
	a.mu.Unlock()
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
	excludeRegex, err := compileExcludeRegexes(opts.ExcludeRegexes)
	if err != nil {
		atomic.StoreInt32(&a.running, 0)
		return err
	}

	ctx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.cancelFn = cancel
	a.jobID = opts.JobID
	a.jobStart = time.Now()
	a.currentFile = ""
	a.mu.Unlock()
	atomic.StoreInt64(&a.filesProc, 0)
	atomic.StoreInt64(&a.bytesXfer, 0)

	defer func() {
		atomic.StoreInt32(&a.running, 0)
		a.mu.Lock()
		a.cancelFn = nil
		a.currentFile = ""
		a.mu.Unlock()
		cancel()
	}()

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
		errCount         int // files that could not be backed up
	)
	seenPaths := make(map[string]struct{})

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
				n, b, hadErr := a.processFile(ctx, workerClient, opts, item.path, item.srcDir)
				mu.Lock()
				if n > 0 {
					filesProcessed += n
					bytesTransferred += b
				}
				if hadErr {
					errCount++
				}
				mu.Unlock()
				if n > 0 {
					atomic.AddInt64(&a.filesProc, int64(n))
				}
			}
		}(i)
	}

	var walkErrCount int // walk-level errors (inaccessible directories/files)

	for _, srcDir := range opts.SourceDirs {
		if ctx.Err() != nil {
			break
		}

		walkErr := filepath.WalkDir(srcDir, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				log.Printf("walk error at %s: %v", path, err)
				_ = a.db.InsertJobError(opts.JobID, path, "walk", err.Error())
				mu.Lock()
				walkErrCount++
				mu.Unlock()
				return nil
			}
			if d.IsDir() {
				if isExcluded(path, opts.ExcludePaths, excludeRegex) {
					return filepath.SkipDir
				}
				return nil
			}
			if isExcluded(path, opts.ExcludePaths, excludeRegex) {
				return nil
			}
			seenPaths[path] = struct{}{}
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

	// Optional source-deletion retention/cleanup.
	if !errors.Is(ctx.Err(), context.Canceled) {
		if _, retentionErrs := a.applyDeletedSourceRetention(ctx, opts, seenPaths, excludeRegex); retentionErrs > 0 {
			mu.Lock()
			errCount += retentionErrs
			mu.Unlock()
		}
	}

	// Update job stats.
	totalErrors := errCount + walkErrCount
	status := "completed"
	errMsg := ""
	if errors.Is(ctx.Err(), context.Canceled) {
		// Job was stopped by the user.
		status = "stopped"
		errMsg = "job was stopped by user"
	} else if totalErrors > 0 {
		status = "completed_with_errors"
		errMsg = fmt.Sprintf("%d file(s) could not be backed up", totalErrors)
	}
	_ = a.db.UpdateJob(opts.JobID, status, filesProcessed, bytesTransferred, errMsg)
	log.Printf("backup job %d %s: %d files, %d bytes, %d errors", opts.JobID, status, filesProcessed, bytesTransferred, totalErrors)
	if totalErrors > 0 && !errors.Is(ctx.Err(), context.Canceled) {
		notify.SendPartialFailure(a.cfg.NtfyTopic, opts.JobID, totalErrors)
	}
	return nil
}

func isWithinSourceDirs(path string, sourceDirs []string) bool {
	cleanPath := filepath.Clean(path)
	for _, src := range sourceDirs {
		cleanSrc := filepath.Clean(src)
		if cleanPath == cleanSrc || strings.HasPrefix(cleanPath, cleanSrc+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

// applyDeletedSourceRetention marks missing files and purges expired retained
// files when deleted-source retention is enabled.
func (a *Agent) applyDeletedSourceRetention(ctx context.Context, opts BackupOptions, seenPaths map[string]struct{}, excludeRegex []*regexp.Regexp) (removed int, errs int) {
	retention, ok := a.cfg.DeletedRetentionDuration()
	if !ok {
		return 0, 0
	}
	entries, err := a.db.ListFileLifecycleEntries()
	if err != nil {
		log.Printf("deleted-retention: list files: %v", err)
		return 0, 1
	}

	now := time.Now().UTC()
	cutoff := now.Add(-retention)
	var expiredIDs []int64
	var expiredPaths []string

	for _, e := range entries {
		if !isWithinSourceDirs(e.SourcePath, opts.SourceDirs) || isExcluded(e.SourcePath, opts.ExcludePaths, excludeRegex) {
			continue
		}
		if _, exists := seenPaths[e.SourcePath]; exists {
			if e.DeletedAt != nil {
				if err := a.db.ClearFileDeleted(e.SourcePath); err != nil {
					log.Printf("deleted-retention: clear marker %s: %v", e.SourcePath, err)
					errs++
				}
			}
			continue
		}
		if e.DeletedAt == nil {
			if err := a.db.MarkFileDeletedIfUnset(e.SourcePath, now); err != nil {
				log.Printf("deleted-retention: mark deleted %s: %v", e.SourcePath, err)
				errs++
			}
			continue
		}
		if !e.DeletedAt.After(cutoff) {
			expiredIDs = append(expiredIDs, e.ID)
			expiredPaths = append(expiredPaths, e.SourcePath)
		}
	}

	if len(expiredIDs) == 0 || ctx.Err() != nil {
		return 0, errs
	}

	blobIDs, err := a.db.ListBlobIDsByFileIDs(expiredIDs)
	if err != nil {
		log.Printf("deleted-retention: list blob ids: %v", err)
		return 0, errs + 1
	}

	client, err := transfer.NewClient(
		a.cfg.RemoteHost,
		a.cfg.RemotePort,
		a.cfg.RemoteUser,
		a.cfg.RemoteKeyPath,
		a.cfg.RemotePassword,
	)
	if err != nil {
		log.Printf("deleted-retention: sftp connect: %v", err)
		return 0, errs + 1
	}
	defer client.Close()

	for _, blobID := range blobIDs {
		if ctx.Err() != nil {
			return 0, errs
		}
		if err := client.DeleteBlob(a.cfg.RemoteBasePath, blobID); err != nil && !isRemoteBlobMissing(err) {
			log.Printf("deleted-retention: delete blob %s: %v", blobID, err)
			errs++
		}
	}

	if err := a.db.DeleteFilesByIDs(expiredIDs); err != nil {
		log.Printf("deleted-retention: delete db records: %v", err)
		return 0, errs + 1
	}
	sort.Strings(expiredPaths)
	for _, p := range expiredPaths {
		log.Printf("deleted-retention: removed expired deleted file: %s", p)
	}
	log.Printf("deleted-retention: removed %d expired deleted file record(s)", len(expiredIDs))
	return len(expiredIDs), errs
}

// processFile checks whether a file needs backing up, and if so encrypts and
// uploads it. It returns (1, fileSize, false) when the file was backed up,
// (0, 0, false) when it was skipped (unchanged), and (0, 0, true) when an
// error prevented the file from being backed up.
func (a *Agent) processFile(ctx context.Context, client *transfer.Client, opts BackupOptions, path, srcDir string) (int, int64, bool) {
	if ctx.Err() != nil {
		return 0, 0, false
	}

	// Fast stat-based pre-check: skip the SHA-256 read if size and mtime are
	// identical to the last backed-up version.
	info, err := os.Stat(path)
	if err != nil {
		log.Printf("stat error %s: %v", path, err)
		_ = a.db.InsertJobError(opts.JobID, path, "stat", err.Error())
		return 0, 0, true
	}
	currSize := info.Size()
	currMtimeNS := info.ModTime().UnixNano()

	storedHash, storedSize, storedMtimeNS, err := a.db.GetLatestVersionInfo(path)
	if err != nil {
		log.Printf("db info check error %s: %v", path, err)
		_ = a.db.InsertJobError(opts.JobID, path, "db", err.Error())
		return 0, 0, true
	}
	if storedHash != "" && currSize == storedSize && currMtimeNS == storedMtimeNS {
		// Stat (size + mtime) is identical to the last backed-up version.
		// This is the same heuristic used by rsync and most backup tools: a
		// matching size+mtime almost always means unchanged content. Files
		// where the mtime is deliberately reset after modification (e.g. via
		// touch -t) will be missed until the next hash-verification run.
		return 0, 0, false
	}

	// Stat changed (or no prior version); verify content with SHA-256.
	hash, err := HashFile(path)
	if err != nil {
		log.Printf("hash error %s: %v", path, err)
		_ = a.db.InsertJobError(opts.JobID, path, "hash", err.Error())
		return 0, 0, true
	}
	if storedHash == hash {
		// Content unchanged despite stat difference (e.g. mtime was reset).
		// Update the stored mtime so future runs skip the hash computation.
		if err := a.db.UpdateLatestVersionMtime(path, currMtimeNS); err != nil {
			log.Printf("update mtime error %s: %v", path, err)
		}
		return 0, 0, false
	}

	// Content changed; encrypt and upload.
	a.mu.Lock()
	a.currentFile = path
	a.mu.Unlock()

	f, err := os.Open(path)
	if err != nil {
		log.Printf("open error %s: %v", path, err)
		_ = a.db.InsertJobError(opts.JobID, path, "open", err.Error())
		return 0, 0, true
	}
	defer f.Close()

	blobID := uuid.New().String()

	pr, pw := io.Pipe()
	encErrCh := make(chan error, 1)
	go func() {
		var err error
		if a.cfg.CompressionEnabled {
			err = CompressAndEncryptFile(a.key, f, pw)
		} else {
			err = EncryptFile(a.key, f, pw)
		}
		pw.CloseWithError(err)
		encErrCh <- err
	}()

	uploadReader := &hashingReader{
		h: sha256.New(),
		r: &countingReader{
			r: pr,
			onRead: func(n int) {
				atomic.AddInt64(&a.bytesXfer, int64(n))
			},
		},
	}
	uploadErr := client.UploadBlob(
		a.cfg.RemoteBasePath,
		blobID,
		uploadReader,
	)
	if uploadErr != nil {
		_ = pr.CloseWithError(uploadErr)
	} else {
		_ = pr.Close()
	}
	encErr := <-encErrCh

	if uploadErr != nil {
		log.Printf("upload error %s: %v", path, uploadErr)
		_ = a.db.InsertJobError(opts.JobID, path, "upload", uploadErr.Error())
		return 0, 0, true
	}
	if encErr != nil {
		log.Printf("encrypt error %s: %v", path, encErr)
		_ = a.db.InsertJobError(opts.JobID, path, "encrypt", encErr.Error())
		return 0, 0, true
	}

	blobHash := uploadReader.Sum()

	// Build display path relative to source dir.
	displayPath := path
	if rel, err := filepath.Rel(srcDir, path); err == nil {
		displayPath = filepath.Join(filepath.Base(srcDir), rel)
	}
	displayPath = strings.ReplaceAll(displayPath, string(os.PathSeparator), "/")

	// Store version in DB.
	oldBlobID, err := a.db.UpsertFileVersion(path, displayPath, blobID, hash, blobHash, currSize, currMtimeNS, opts.JobID)
	if err != nil {
		log.Printf("db upsert error %s: %v", path, err)
		_ = a.db.InsertJobError(opts.JobID, path, "db", err.Error())
		return 0, 0, true
	}

	// Delete evicted blob from remote if any.
	if oldBlobID != "" {
		if err := client.DeleteBlob(a.cfg.RemoteBasePath, oldBlobID); err != nil {
			log.Printf("delete old blob error %s: %v", oldBlobID, err)
		}
	}

	log.Printf("backed up: %s -> %s", path, blobID)
	return 1, currSize, false
}

type countingReader struct {
	r      io.Reader
	onRead func(int)
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if n > 0 && c.onRead != nil {
		c.onRead(n)
	}
	return n, err
}

type hashingReader struct {
	r io.Reader
	h hash.Hash
}

func (hr *hashingReader) Read(p []byte) (int, error) {
	n, err := hr.r.Read(p)
	if n > 0 {
		_, _ = hr.h.Write(p[:n])
	}
	return n, err
}

func (hr *hashingReader) Sum() string {
	return fmt.Sprintf("%x", hr.h.Sum(nil))
}

func compileExcludeRegexes(patterns []string) ([]*regexp.Regexp, error) {
	if len(patterns) == 0 {
		return nil, nil
	}
	compiled := make([]*regexp.Regexp, 0, len(patterns))
	for _, pattern := range patterns {
		if pattern == "" {
			continue
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid exclude regex %q: %w", pattern, err)
		}
		compiled = append(compiled, re)
	}
	return compiled, nil
}

// isExcluded reports whether path matches any of the given exclude paths.
// A path is excluded if it equals an exclude entry or is nested under one.
func isExcluded(path string, excludePaths []string, excludeRegex []*regexp.Regexp) bool {
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
	for _, re := range excludeRegex {
		if re.MatchString(path) {
			return true
		}
	}
	return false
}
