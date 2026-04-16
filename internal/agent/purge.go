package agent

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/seanmatheny/coldcrypt/internal/transfer"
)

// PurgeResult summarizes a purge operation.
type PurgeResult struct {
	TotalBlobs          int `json:"total_blobs"`
	RemoteDeleted       int `json:"remote_deleted"`
	RemoteMissing       int `json:"remote_missing"`
	RemoteDeleteErrors  int `json:"remote_delete_errors"`
	DatabaseRecordsGone int `json:"database_records_removed"`
}

// PurgeAllBackups deletes every backed-up blob from the remote SFTP server and
// removes all file/version records from the local database. It is an
// irreversible operation; callers must obtain explicit user confirmation before
// invoking this method.
func (a *Agent) PurgeAllBackups(ctx context.Context) error {
	return a.PurgeByPrefix(ctx, "")
}

func isRemoteBlobMissing(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrNotExist) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "file does not exist") || strings.Contains(msg, "no such file")
}

// PurgeByPrefix deletes all backed-up blobs for files whose display_path starts
// with the given prefix from the remote SFTP server and removes matching records
// from the local database. If prefix is empty, all backups are purged
// (equivalent to PurgeAllBackups). It is an irreversible operation; callers
// must obtain explicit user confirmation before invoking this method.
//
// Ordering: remote blobs are deleted first so that, if the DB cleanup fails,
// the user can simply retry (the DB still records the now-absent blobs, but
// running purge again will clear them). The inverse order would leave orphaned
// DB records pointing to blobs that no longer exist, which is harder to recover.
func (a *Agent) PurgeByPrefix(ctx context.Context, displayPrefix string) error {
	_, err := a.PurgeByPrefixWithReport(ctx, displayPrefix)
	return err
}

// PurgeByPrefixWithReport behaves like PurgeByPrefix but returns a structured
// result so the UI can notify users about missing remote blobs.
func (a *Agent) PurgeByPrefixWithReport(ctx context.Context, displayPrefix string) (PurgeResult, error) {
	client, err := transfer.NewClient(
		a.cfg.RemoteHost,
		a.cfg.RemotePort,
		a.cfg.RemoteUser,
		a.cfg.RemoteKeyPath,
		a.cfg.RemotePassword,
	)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("sftp connect: %w", err)
	}
	defer client.Close()

	// Collect blob IDs for the matching files without modifying the database yet.
	blobIDs, err := a.db.ListBlobIDsByDisplayPrefix(displayPrefix)
	if err != nil {
		return PurgeResult{}, fmt.Errorf("list blob IDs: %w", err)
	}
	result := PurgeResult{TotalBlobs: len(blobIDs), DatabaseRecordsGone: len(blobIDs)}

	// Delete remote blobs first. Errors are logged but do not stop the purge;
	// an unreachable/already-absent blob should not block the DB cleanup.
	for _, blobID := range blobIDs {
		if ctx.Err() != nil {
			return result, ctx.Err()
		}
		if err := client.DeleteBlob(a.cfg.RemoteBasePath, blobID); err != nil {
			if isRemoteBlobMissing(err) {
				log.Printf("purge: blob %s already absent on remote; removing local DB record", blobID)
				result.RemoteMissing++
				continue
			}
			log.Printf("purge: delete blob %s failed: %v", blobID, err)
			result.RemoteDeleteErrors++
			continue
		}
		result.RemoteDeleted++
	}

	// Clear local database records.
	if err := a.db.DeleteFilesByDisplayPrefix(displayPrefix); err != nil {
		return result, fmt.Errorf("delete db records: %w", err)
	}

	label := "all"
	if displayPrefix != "" {
		label = fmt.Sprintf("%q", displayPrefix)
	}
	log.Printf(
		"purge complete (%s): %d remote deleted, %d missing remotely, %d remote delete errors",
		label, result.RemoteDeleted, result.RemoteMissing, result.RemoteDeleteErrors,
	)
	if result.RemoteDeleteErrors > 0 {
		return result, fmt.Errorf("purge completed with %d remote delete error(s); check logs for details", result.RemoteDeleteErrors)
	}
	return result, nil
}
