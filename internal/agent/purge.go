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
//
// Ordering: remote blobs are deleted first so that, if the DB cleanup fails,
// the user can simply retry (the DB still records the now-absent blobs, but
// running purge again will clear them). The inverse order would leave orphaned
// DB records pointing to blobs that no longer exist, which is harder to recover.
func (a *Agent) PurgeAllBackups(ctx context.Context) error {
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

	// Collect all blob IDs without modifying the database yet.
	blobIDs, err := a.db.ListAllBlobIDs()
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
	if err := a.db.DeleteAllFiles(); err != nil {
		return fmt.Errorf("delete db records: %w", err)
	}

	log.Printf("purge complete: %d blobs removed, %d remote delete errors", len(blobIDs), deleteErrors)
	if deleteErrors > 0 {
		return fmt.Errorf("purge completed with %d remote delete error(s); check logs for details", deleteErrors)
	}
	return nil
}
