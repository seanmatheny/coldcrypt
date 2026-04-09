package agent

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/seanmatheny/coldcrypt/internal/transfer"
)

// RestoreFile downloads and decrypts a specific file version to outPath.
func (a *Agent) RestoreFile(ctx context.Context, fileID int64, versionNum int, outPath string) error {
	versions, err := a.db.GetFileVersions(fileID)
	if err != nil {
		return fmt.Errorf("get versions: %w", err)
	}

	var blobID string
	for _, v := range versions {
		if v.VersionNum == versionNum {
			blobID = v.BlobID
			break
		}
	}
	if blobID == "" {
		// Fall back to version by index if version_num doesn't match exactly.
		// versions are ordered newest-first; versionNum=1 means the most recent.
		idx := versionNum - 1
		if idx < 0 || idx >= len(versions) {
			return fmt.Errorf("version %d not found for file %d", versionNum, fileID)
		}
		blobID = versions[idx].BlobID
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

	rc, err := client.DownloadBlob(a.cfg.RemoteBasePath, blobID)
	if err != nil {
		return fmt.Errorf("download blob: %w", err)
	}
	defer rc.Close()

	// Ensure output directory exists.
	if err := os.MkdirAll(filepath.Dir(outPath), 0755); err != nil {
		return fmt.Errorf("create output dir: %w", err)
	}

	outFile, err := os.Create(outPath)
	if err != nil {
		return fmt.Errorf("create output file: %w", err)
	}
	defer outFile.Close()

	if err := DecryptFile(a.key, rc, outFile); err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}

	return nil
}
