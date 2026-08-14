package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/seanmatheny/coldcrypt/internal/notify"
	"github.com/seanmatheny/coldcrypt/internal/transfer"
)

const scanWorkers = 4
const maxInconsistencyPathListLength = 800

// RunScan verifies backed-up blobs against their recorded hashes. When
// sourceDirs is non-empty the scan is scoped to files whose source path lies
// within one of those directories (per-job scan); an empty slice scans the
// whole archive.
func (a *Agent) RunScan(ctx context.Context, jobID int64, sourceDirs []string) error {
	if !atomic.CompareAndSwapInt32(&a.scanRunning, 0, 1) {
		return ErrScanAlreadyRunning
	}
	ctx, cancel := context.WithCancel(ctx)
	a.mu.Lock()
	a.scanCancelFn = cancel
	a.scanJobID = jobID
	a.scanJobStart = time.Now()
	a.scanCurrentFile = ""
	a.mu.Unlock()
	atomic.StoreInt64(&a.scanFilesProc, 0)
	atomic.StoreInt64(&a.scanTotal, 0)

	defer func() {
		atomic.StoreInt32(&a.scanRunning, 0)
		a.mu.Lock()
		a.scanCancelFn = nil
		a.scanCurrentFile = ""
		a.scanJobID = 0
		a.scanJobStart = time.Time{}
		a.mu.Unlock()
		cancel()
	}()

	if a.IsRunning() {
		log.Printf("scan: note: a backup job is also in progress")
	}

	entries, err := a.db.ListLatestVersionsForScan()
	if err != nil {
		return fmt.Errorf("list scan entries: %w", err)
	}
	if len(sourceDirs) > 0 {
		scoped := entries[:0]
		for _, e := range entries {
			if isWithinSourceDirs(e.SourcePath, sourceDirs) {
				scoped = append(scoped, e)
			}
		}
		entries = scoped
	}
	atomic.StoreInt64(&a.scanTotal, int64(len(entries)))

	workCh := make(chan int, 64)
	var (
		mu              sync.Mutex
		inconsistencies []string
		errCount        int
		filesScanned    int
	)

	var wg sync.WaitGroup
	for i := 0; i < scanWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range workCh {
				if ctx.Err() != nil {
					return
				}
				entry := entries[idx]
				a.mu.Lock()
				a.scanCurrentFile = entry.SourcePath
				a.mu.Unlock()

				client, err := transfer.NewClient(
					a.cfg.RemoteHost, a.cfg.RemotePort,
					a.cfg.RemoteUser, a.cfg.RemoteKeyPath, a.cfg.RemotePassword,
				)
				if err != nil {
					log.Printf("scan worker: connect error: %v", err)
					atomic.AddInt64(&a.scanFilesProc, 1)
					mu.Lock()
					filesScanned++
					errCount++
					mu.Unlock()
					continue
				}
				remoteHash, err := client.HashBlob(a.cfg.RemoteBasePath, entry.BlobID)
				_ = client.Close()
				atomic.AddInt64(&a.scanFilesProc, 1)
				mu.Lock()
				filesScanned++
				if err != nil {
					log.Printf("scan: hash error for %s (blob %s): %v", entry.SourcePath, entry.BlobID, err)
					errCount++
				} else if remoteHash != entry.BlobHash {
					log.Printf("scan: INCONSISTENCY detected: %s (blob %s): expected %s got %s",
						entry.SourcePath, entry.BlobID, entry.BlobHash, remoteHash)
					inconsistencies = append(inconsistencies, entry.SourcePath)
				}
				mu.Unlock()
			}
		}()
	}

	for i := range entries {
		if ctx.Err() != nil {
			break
		}
		workCh <- i
	}
	close(workCh)
	wg.Wait()

	status := "completed"
	var errMsg string
	if errors.Is(ctx.Err(), context.Canceled) {
		status = "stopped"
		errMsg = "scan was stopped by user"
	} else if len(inconsistencies) > 0 || errCount > 0 {
		status = "completed_with_errors"
		parts := []string{fmt.Sprintf("%d files scanned", filesScanned)}
		if len(inconsistencies) > 0 {
			pathList := strings.Join(inconsistencies, ", ")
			pathRunes := []rune(pathList)
			if len(pathRunes) > maxInconsistencyPathListLength {
				pathList = string(pathRunes[:maxInconsistencyPathListLength]) + "..."
			}
			parts = append(parts, fmt.Sprintf("%d inconsistenc(ies) found: %s", len(inconsistencies), pathList))
		}
		if errCount > 0 {
			parts = append(parts, fmt.Sprintf("%d file(s) could not be scanned", errCount))
		}
		errMsg = strings.Join(parts, "; ")
	}

	_ = a.db.UpdateJob(jobID, status, filesScanned, 0, errMsg)
	log.Printf("scan job %d %s: %d files, %d inconsistencies, %d errors",
		jobID, status, filesScanned, len(inconsistencies), errCount)

	if (len(inconsistencies) > 0 || errCount > 0) && !errors.Is(ctx.Err(), context.Canceled) {
		notify.SendScanIssues(a.cfg.NtfyTopic, jobID, filesScanned, len(inconsistencies), errCount)
	}
	return nil
}
