package agent

import (
	"context"
	"fmt"
	"log"

	"github.com/seanmatheny/coldcrypt/internal/transfer"
)

// PurgeAllBackups deletes every backed-up blob from the remote SFTP server and
// removes all file/version records from the local database. It is an
// irreversible operation; callers must obtain explicit user confirmation before
// invoking this method.
func (a *Agent) PurgeAllBackups(ctx context.Context) error {
	return a.PurgeByPrefix(ctx, "")
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

	// Collect blob IDs for the matching files without modifying the database yet.
	blobIDs, err := a.db.ListBlobIDsByDisplayPrefix(displayPrefix)
	if err != nil {
		return fmt.Errorf("list blob IDs: %w", err)
	}

	// Delete remote blobs first. Errors are logged but do not stop the purge;
	// an unreachable/already-absent blob should not block the DB cleanup.
	var deleteErrors int
	for _, blobID := range blobIDs {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err := client.DeleteBlob(a.cfg.RemoteBasePath, blobID); err != nil {
			log.Printf("purge: delete blob %s: %v", blobID, err)
			deleteErrors++
		}
	}

	// Clear local database records.
	if err := a.db.DeleteFilesByDisplayPrefix(displayPrefix); err != nil {
		return fmt.Errorf("delete db records: %w", err)
	}

	label := "all"
	if displayPrefix != "" {
		label = fmt.Sprintf("%q", displayPrefix)
	}
	log.Printf("purge complete (%s): %d blobs removed, %d remote delete errors", label, len(blobIDs), deleteErrors)
	if deleteErrors > 0 {
		return fmt.Errorf("purge completed with %d remote delete error(s); check logs for details", deleteErrors)
	}
	return nil
}
