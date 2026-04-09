package agent

import (
"context"
"fmt"
"io"
"log"
"os"
"path/filepath"

"github.com/seanmatheny/coldcrypt/internal/transfer"
)

// RestoreFile downloads and decrypts a specific file version to outPath.
// outPath must be an absolute path. If outPath is an existing directory the
// original filename is appended automatically (standard cp behaviour).
func (a *Agent) RestoreFile(ctx context.Context, fileID int64, versionNum int, outPath string) error {
cleanPath := filepath.Clean(outPath)
if !filepath.IsAbs(cleanPath) {
return fmt.Errorf("out_path must be an absolute path")
}

// If outPath is an existing directory, append the original filename.
if info, statErr := os.Stat(cleanPath); statErr == nil && info.IsDir() {
fileEntry, err := a.db.GetFileByID(fileID)
if err != nil {
return fmt.Errorf("get file entry: %w", err)
}
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
return fmt.Errorf("sftp connect: %w", err)
}
defer client.Close()

return a.restoreOne(ctx, client, fileID, versionNum, cleanPath)
}

// RestoreByPrefix downloads and decrypts all files whose display_path starts
// with displayPrefix into outDir, preserving the directory structure.
// If displayPrefix is empty every backed-up file is restored.
// versionNum=0 selects the latest version of each file.
func (a *Agent) RestoreByPrefix(ctx context.Context, displayPrefix, outDir string, versionNum int) error {
cleanDir := filepath.Clean(outDir)
if !filepath.IsAbs(cleanDir) {
return fmt.Errorf("out_path must be an absolute path")
}

files, err := a.db.ListFilesByDisplayPrefix(displayPrefix)
if err != nil {
return fmt.Errorf("list files: %w", err)
}
if len(files) == 0 {
log.Printf("restore prefix %q: no files found", displayPrefix)
return nil
}

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

var errCount int
for _, f := range files {
if ctx.Err() != nil {
break
}
dest := filepath.Join(cleanDir, filepath.FromSlash(f.DisplayPath))
if err := a.restoreOne(ctx, client, f.ID, versionNum, dest); err != nil {
log.Printf("restore file %d (%s) error: %v", f.ID, f.DisplayPath, err)
errCount++
} else {
log.Printf("restored: %s -> %s", f.DisplayPath, dest)
}
}

log.Printf("restore prefix %q done: %d files, %d errors", displayPrefix, len(files), errCount)
return nil
}

// DownloadFile downloads and decrypts a specific file version, writing the
// plaintext to dst. It returns the original base filename so the caller can set
// an appropriate Content-Disposition header.
func (a *Agent) DownloadFile(ctx context.Context, fileID int64, versionNum int, dst io.Writer) (string, error) {
	fileEntry, err := a.db.GetFileByID(fileID)
	if err != nil {
		return "", fmt.Errorf("get file entry: %w", err)
	}
	filename := filepath.Base(fileEntry.SourcePath)

	client, err := transfer.NewClient(
		a.cfg.RemoteHost,
		a.cfg.RemotePort,
		a.cfg.RemoteUser,
		a.cfg.RemoteKeyPath,
		a.cfg.RemotePassword,
	)
	if err != nil {
		return "", fmt.Errorf("sftp connect: %w", err)
	}
	defer client.Close()

	versions, err := a.db.GetFileVersions(fileID)
	if err != nil {
		return "", fmt.Errorf("get versions: %w", err)
	}
	if len(versions) == 0 {
		return "", fmt.Errorf("no versions for file %d", fileID)
	}

	var blobID string
	if versionNum == 0 {
		blobID = versions[0].BlobID
	} else {
		for _, v := range versions {
			if v.VersionNum == versionNum {
				blobID = v.BlobID
				break
			}
		}
		if blobID == "" {
			idx := versionNum - 1
			if idx < 0 || idx >= len(versions) {
				return "", fmt.Errorf("version %d not found for file %d", versionNum, fileID)
			}
			blobID = versions[idx].BlobID
		}
	}

	rc, err := client.DownloadBlob(a.cfg.RemoteBasePath, blobID)
	if err != nil {
		return "", fmt.Errorf("download blob: %w", err)
	}
	defer rc.Close()

	if err := DecryptFile(a.key, rc, dst); err != nil {
		return "", fmt.Errorf("decrypt: %w", err)
	}
	return filename, nil
}

// restoreOne downloads and decrypts a single file version using an existing
// SFTP client. outPath must be the final destination file path (not a directory).
func (a *Agent) restoreOne(ctx context.Context, client *transfer.Client, fileID int64, versionNum int, outPath string) error {
versions, err := a.db.GetFileVersions(fileID)
if err != nil {
return fmt.Errorf("get versions: %w", err)
}
if len(versions) == 0 {
return fmt.Errorf("no versions for file %d", fileID)
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
return fmt.Errorf("version %d not found for file %d", versionNum, fileID)
}
blobID = versions[idx].BlobID
}
}

rc, err := client.DownloadBlob(a.cfg.RemoteBasePath, blobID)
if err != nil {
return fmt.Errorf("download blob: %w", err)
}
defer rc.Close()

if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil { //nolint:gosec // outPath is abs-cleaned by callers
return fmt.Errorf("create output dir: %w", err)
}

outFile, err := os.Create(outPath) //nolint:gosec // outPath is validated by callers
if err != nil {
return fmt.Errorf("create output file: %w", err)
}
defer outFile.Close()

if err := DecryptFile(a.key, rc, outFile); err != nil {
return fmt.Errorf("decrypt: %w", err)
}

return nil
}
