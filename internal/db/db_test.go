package db

import (
	"database/sql"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

func TestListLatestVersionsForScanUsesLatestAndSkipsEmptyBlobHash(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	d, err := New(tmp)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer d.Close()

	jobID, err := d.CreateJob()
	if err != nil {
		t.Fatalf("CreateJob: %v", err)
	}

	if _, err := d.UpsertFileVersion("/src/a.txt", "src/a.txt", "blob-a1", "hash-a", "blobhash-a1", 10, 100, jobID); err != nil {
		t.Fatalf("UpsertFileVersion a1: %v", err)
	}
	if _, err := d.UpsertFileVersion("/src/a.txt", "src/a.txt", "blob-a2", "hash-a", "blobhash-a2", 10, 200, jobID); err != nil {
		t.Fatalf("UpsertFileVersion a2: %v", err)
	}
	if _, err := d.UpsertFileVersion("/src/b.txt", "src/b.txt", "blob-b1", "hash-b", "", 10, 100, jobID); err != nil {
		t.Fatalf("UpsertFileVersion b1: %v", err)
	}

	entries, err := d.ListLatestVersionsForScan()
	if err != nil {
		t.Fatalf("ListLatestVersionsForScan: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("expected 1 scan entry, got %d", len(entries))
	}
	if entries[0].SourcePath != "/src/a.txt" || entries[0].BlobID != "blob-a2" || entries[0].BlobHash != "blobhash-a2" {
		t.Fatalf("unexpected scan entry: %+v", entries[0])
	}
}

func TestNewMigratesBlobHashColumn(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	legacyPath := filepath.Join(tmp, "coldcrypt.db")
	conn, err := sql.Open("sqlite", legacyPath)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	legacySchema := `
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path TEXT NOT NULL UNIQUE,
    display_path TEXT NOT NULL,
    deleted_at DATETIME
);
CREATE TABLE IF NOT EXISTS file_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id),
    version_num INTEGER NOT NULL,
    blob_id TEXT NOT NULL,
    size INTEGER NOT NULL,
    hash TEXT NOT NULL,
    mtime_ns INTEGER NOT NULL DEFAULT 0,
    encrypted_at DATETIME NOT NULL,
    job_id INTEGER NOT NULL,
    UNIQUE(file_id, version_num)
);
CREATE TABLE IF NOT EXISTS backup_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    job_type TEXT NOT NULL DEFAULT 'backup',
    started_at DATETIME NOT NULL,
    completed_at DATETIME,
    status TEXT NOT NULL DEFAULT 'running',
    files_processed INTEGER DEFAULT 0,
    bytes_transferred INTEGER DEFAULT 0,
    error_message TEXT
);`
	if _, err := conn.Exec(legacySchema); err != nil {
		t.Fatalf("create legacy schema: %v", err)
	}
	_ = conn.Close()

	d, err := New(tmp)
	if err != nil {
		t.Fatalf("New migrate: %v", err)
	}
	defer d.Close()

	rows, err := d.conn.Query(`PRAGMA table_info(file_versions)`)
	if err != nil {
		t.Fatalf("table_info: %v", err)
	}
	defer rows.Close()

	found := false
	for rows.Next() {
		var cid int
		var name, typ string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			t.Fatalf("scan table_info: %v", err)
		}
		if name == "blob_hash" {
			found = true
			break
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("rows err: %v", err)
	}
	if !found {
		t.Fatalf("blob_hash column not found after migration")
	}
}
