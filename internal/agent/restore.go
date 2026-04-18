package agent

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/seanmatheny/coldcrypt/internal/transfer"
)

// RestoreFile downloads and decrypts a specific file version to outPath.
// outPath must be an absolute path. If outPath is an existing directory the
// original filename is appended automatically (standard cp behaviour).
func (a *Agent) RestoreFile(ctx context.Context, jobID, fileID int64, versionNum int, outPath string) (filesProcessed int, bytesTransferred int64, err error) {
	if err := a.startRestore(jobID); err != nil {
		return 0, 0, err
	}
	defer a.finishRestore()

	cleanPath := filepath.Clean(outPath)
	if !filepath.IsAbs(cleanPath) {
		return 0, 0, fmt.Errorf("out_path must be an absolute path")
	}

	fileEntry, err := a.db.GetFileByID(fileID)
	if err != nil {
		return 0, 0, fmt.Errorf("get file entry: %w", err)
	}
	a.setRestoreCurrentFile(fileEntry.DisplayPath)

	// If outPath is an existing directory, append the original filename.
	if info, statErr := os.Stat(cleanPath); statErr == nil && info.IsDir() {
		cleanPath = filepath.Join(cleanPath, filepath.Base(fileEntry.SourcePath))
	}

	client, err := transfer.NewClient(
		a.cfg.RemoteHost,
		a.cfg.RemotePort,
		a.cfg.RemoteUser,
		a.cfg.RemoteKeyPath,
		a.cfg.RemotePassword,
	)
	if err != nil {
		return 0, 0, fmt.Errorf("sftp connect: %w", err)
	}
	defer client.Close()

	bytes, err := a.restoreOne(ctx, client, fileID, versionNum, cleanPath)
	if err != nil {
		log.Printf("restore file %d error: %v", fileID, err)
		return 0, bytes, err
	}
	filesProcessed++
	atomic.AddInt64(&a.restoreFilesProc, 1)
	log.Printf("restored file %d -> %s", fileID, cleanPath)
	return filesProcessed, bytes, nil
}

// RestoreByPrefix downloads and decrypts all files whose display_path starts
// with displayPrefix into outDir, preserving the directory structure.
// If displayPrefix is empty every backed-up file is restored.
// versionNum=0 selects the latest version of each file.
func (a *Agent) RestoreByPrefix(ctx context.Context, jobID int64, displayPrefix, outDir string, versionNum int) (filesProcessed int, bytesTransferred int64, errCount int, err error) {
	if err := a.startRestore(jobID); err != nil {
		return 0, 0, 0, err
	}
	defer a.finishRestore()

	cleanDir := filepath.Clean(outDir)
	if !filepath.IsAbs(cleanDir) {
		return 0, 0, 0, fmt.Errorf("out_path must be an absolute path")
	}

	files, err := a.db.ListFilesByDisplayPrefix(displayPrefix)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("list files: %w", err)
	}
	if len(files) == 0 {
		log.Printf("restore prefix %q: no files found", displayPrefix)
		return 0, 0, 0, nil
	}

	client, err := transfer.NewClient(
		a.cfg.RemoteHost,
		a.cfg.RemotePort,
		a.cfg.RemoteUser,
		a.cfg.RemoteKeyPath,
		a.cfg.RemotePassword,
	)
	if err != nil {
		return 0, 0, 0, fmt.Errorf("sftp connect: %w", err)
	}
	defer client.Close()

	for _, f := range files {
		if ctx.Err() != nil {
			break
		}
		a.setRestoreCurrentFile(f.DisplayPath)
		dest := filepath.Join(cleanDir, filepath.FromSlash(f.DisplayPath))
		bytes, err := a.restoreOne(ctx, client, f.ID, versionNum, dest)
		bytesTransferred += bytes
		if err != nil {
			log.Printf("restore file %d (%s) error: %v", f.ID, f.DisplayPath, err)
			errCount++
		} else {
			filesProcessed++
			atomic.AddInt64(&a.restoreFilesProc, 1)
			log.Printf("restored: %s -> %s", f.DisplayPath, dest)
		}
	}

	log.Printf("restore prefix %q done: %d files, %d errors", displayPrefix, len(files), errCount)
	return filesProcessed, bytesTransferred, errCount, nil
}

// restoreOne downloads and decrypts a single file version using an existing
// SFTP client. outPath must be the final destination file path (not a directory).
func (a *Agent) restoreOne(ctx context.Context, client *transfer.Client, fileID int64, versionNum int, outPath string) (int64, error) {
	versions, err := a.db.GetFileVersions(fileID)
	if err != nil {
		return 0, fmt.Errorf("get versions: %w", err)
	}
	if len(versions) == 0 {
		return 0, fmt.Errorf("no versions for file %d", fileID)
	}

	var blobID string
	if versionNum == 0 {
		// Latest version (versions are ordered newest first).
		blobID = versions[0].BlobID
	} else {
		for _, v := range versions {
			if v.VersionNum == versionNum {
				blobID = v.BlobID
				break
			}
		}
		if blobID == "" {
			// Fall back to positional index.
			idx := versionNum - 1
			if idx < 0 || idx >= len(versions) {
				return 0, fmt.Errorf("version %d not found for file %d", versionNum, fileID)
			}
			blobID = versions[idx].BlobID
		}
	}

	rc, err := client.DownloadBlob(a.cfg.RemoteBasePath, blobID)
	if err != nil {
		return 0, fmt.Errorf("download blob: %w", err)
	}
	defer rc.Close()

	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil { //nolint:gosec // outPath is abs-cleaned by callers
		return 0, fmt.Errorf("create output dir: %w", err)
	}

	outFile, err := os.Create(outPath) //nolint:gosec // outPath is validated by callers
	if err != nil {
		return 0, fmt.Errorf("create output file: %w", err)
	}
	defer outFile.Close()

	var bytesRead int64
	counter := &countingReader{
		r: rc,
		onRead: func(n int) {
			bytesRead += int64(n)
		},
	}
	if err := DecryptFile(a.key, counter, outFile); err != nil {
		return bytesRead, fmt.Errorf("decrypt: %w", err)
	}

	atomic.AddInt64(&a.restoreBytesXfer, bytesRead)
	return bytesRead, nil
}
