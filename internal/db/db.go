package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// DB wraps the SQLite database.
type DB struct {
	conn *sql.DB
}

// Job represents a backup job record.
type Job struct {
	ID               int64
	StartedAt        time.Time
	CompletedAt      *time.Time
	Status           string
	FilesProcessed   int
	BytesTransferred int64
	ErrorMessage     string
}

// FileEntry represents a backed-up file.
type FileEntry struct {
	ID          int64
	SourcePath  string
	DisplayPath string
}

// FileVersion represents a single version of a backed-up file.
type FileVersion struct {
	ID          int64
	FileID      int64
	VersionNum  int
	BlobID      string
	Size        int64
	Hash        string
	EncryptedAt time.Time
	JobID       int64
}

// Schedule represents a scheduled backup.
type Schedule struct {
	ID         int64
	Name       string
	CronExpr   string
	SourceDirs []string
	Enabled    bool
	CreatedAt  time.Time
	LastRunAt  *time.Time
}

const schema = `
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_path TEXT NOT NULL UNIQUE,
    display_path TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS file_versions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id INTEGER NOT NULL REFERENCES files(id),
    version_num INTEGER NOT NULL,
    blob_id TEXT NOT NULL,
    size INTEGER NOT NULL,
    hash TEXT NOT NULL,
    encrypted_at DATETIME NOT NULL,
    job_id INTEGER NOT NULL,
    UNIQUE(file_id, version_num)
);

CREATE TABLE IF NOT EXISTS backup_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at DATETIME NOT NULL,
    completed_at DATETIME,
    status TEXT NOT NULL DEFAULT 'running',
    files_processed INTEGER DEFAULT 0,
    bytes_transferred INTEGER DEFAULT 0,
    error_message TEXT
);

CREATE TABLE IF NOT EXISTS schedules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    cron_expr TEXT NOT NULL,
    source_dirs TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT 1,
    created_at DATETIME NOT NULL,
    last_run_at DATETIME
);
`

// New opens or creates the SQLite database in dataDir.
func New(dataDir string) (*DB, error) {
	if dataDir == "" {
		return nil, errors.New("data_dir is not set in config; run 'coldcrypt init <data-dir>' and set data_dir in config.json")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, fmt.Errorf("create data directory %q (check permissions): %w", dataDir, err)
	}
	path := filepath.Join(dataDir, "coldcrypt.db")
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	// Enable WAL mode for better concurrency.
	if _, err := conn.Exec("PRAGMA journal_mode=WAL"); err != nil {
		return nil, fmt.Errorf("wal mode: %w", err)
	}
	if _, err := conn.Exec(schema); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}
	return &DB{conn: conn}, nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

// CreateJob creates a new backup job and returns its ID.
func (d *DB) CreateJob() (int64, error) {
	res, err := d.conn.Exec(
		`INSERT INTO backup_jobs (started_at, status) VALUES (?, 'running')`,
		time.Now().UTC().Format(time.RFC3339),
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// UpdateJob updates the status and stats of a backup job.
func (d *DB) UpdateJob(id int64, status string, filesProcessed int, bytesTransferred int64, errMsg string) error {
	var completedAt interface{}
	if status != "running" {
		completedAt = time.Now().UTC().Format(time.RFC3339)
	}
	_, err := d.conn.Exec(
		`UPDATE backup_jobs SET status=?, files_processed=?, bytes_transferred=?, error_message=?, completed_at=? WHERE id=?`,
		status, filesProcessed, bytesTransferred, errMsg, completedAt, id,
	)
	return err
}

// ListJobs returns up to limit recent backup jobs ordered by start time descending.
func (d *DB) ListJobs(limit int) ([]Job, error) {
	rows, err := d.conn.Query(
		`SELECT id, started_at, completed_at, status, files_processed, bytes_transferred, COALESCE(error_message,'') FROM backup_jobs ORDER BY started_at DESC LIMIT ?`,
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanJobs(rows)
}

// GetJob returns a single backup job by ID.
func (d *DB) GetJob(id int64) (*Job, error) {
	rows, err := d.conn.Query(
		`SELECT id, started_at, completed_at, status, files_processed, bytes_transferred, COALESCE(error_message,'') FROM backup_jobs WHERE id=?`,
		id,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	jobs, err := scanJobs(rows)
	if err != nil {
		return nil, err
	}
	if len(jobs) == 0 {
		return nil, errors.New("job not found")
	}
	return &jobs[0], nil
}

func scanJobs(rows *sql.Rows) ([]Job, error) {
	var jobs []Job
	for rows.Next() {
		var j Job
		var startedAtStr string
		var completedAtStr sql.NullString
		if err := rows.Scan(&j.ID, &startedAtStr, &completedAtStr, &j.Status, &j.FilesProcessed, &j.BytesTransferred, &j.ErrorMessage); err != nil {
			return nil, err
		}
		t, _ := time.Parse(time.RFC3339, startedAtStr)
		j.StartedAt = t
		if completedAtStr.Valid {
			ct, _ := time.Parse(time.RFC3339, completedAtStr.String)
			j.CompletedAt = &ct
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// UpsertFileVersion inserts or rotates versions (max 3).
// Returns the blob ID that was evicted (if any) so the caller can delete it from remote.
func (d *DB) UpsertFileVersion(sourcePath, displayPath, blobID, hash string, size int64, jobID int64) (oldBlobID string, err error) {
	tx, err := d.conn.Begin()
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	// Upsert file record.
	var fileID int64
	err = tx.QueryRow(`SELECT id FROM files WHERE source_path=?`, sourcePath).Scan(&fileID)
	if errors.Is(err, sql.ErrNoRows) {
		res, ierr := tx.Exec(`INSERT INTO files (source_path, display_path) VALUES (?,?)`, sourcePath, displayPath)
		if ierr != nil {
			err = ierr
			return "", err
		}
		fileID, err = res.LastInsertId()
		if err != nil {
			return "", err
		}
	} else if err != nil {
		return "", err
	}

	// Count existing versions.
	var count int
	err = tx.QueryRow(`SELECT COUNT(*) FROM file_versions WHERE file_id=?`, fileID).Scan(&count)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC().Format(time.RFC3339)

	if count < 3 {
		// Add next version number.
		var maxVer sql.NullInt64
		_ = tx.QueryRow(`SELECT MAX(version_num) FROM file_versions WHERE file_id=?`, fileID).Scan(&maxVer)
		nextVer := 1
		if maxVer.Valid {
			nextVer = int(maxVer.Int64) + 1
		}
		_, err = tx.Exec(
			`INSERT INTO file_versions (file_id, version_num, blob_id, size, hash, encrypted_at, job_id) VALUES (?,?,?,?,?,?,?)`,
			fileID, nextVer, blobID, size, hash, now, jobID,
		)
		if err != nil {
			return "", err
		}
	} else {
		// Evict the oldest version (by encrypted_at).
		var evictID int64
		var evictBlob string
		err = tx.QueryRow(
			`SELECT id, blob_id FROM file_versions WHERE file_id=? ORDER BY encrypted_at ASC LIMIT 1`,
			fileID,
		).Scan(&evictID, &evictBlob)
		if err != nil {
			return "", err
		}
		oldBlobID = evictBlob

		// Get next version num.
		var maxVer sql.NullInt64
		_ = tx.QueryRow(`SELECT MAX(version_num) FROM file_versions WHERE file_id=?`, fileID).Scan(&maxVer)
		nextVer := 1
		if maxVer.Valid {
			nextVer = int(maxVer.Int64) + 1
		}

		_, err = tx.Exec(`DELETE FROM file_versions WHERE id=?`, evictID)
		if err != nil {
			return "", err
		}
		_, err = tx.Exec(
			`INSERT INTO file_versions (file_id, version_num, blob_id, size, hash, encrypted_at, job_id) VALUES (?,?,?,?,?,?,?)`,
			fileID, nextVer, blobID, size, hash, now, jobID,
		)
		if err != nil {
			return "", err
		}
	}

	err = tx.Commit()
	return oldBlobID, err
}

// GetLatestVersionHash returns the hash of the most recent version for a source path, or "" if not found.
func (d *DB) GetLatestVersionHash(sourcePath string) (string, error) {
	var hash string
	err := d.conn.QueryRow(
		`SELECT fv.hash FROM file_versions fv
		 JOIN files f ON f.id = fv.file_id
		 WHERE f.source_path=?
		 ORDER BY fv.encrypted_at DESC LIMIT 1`,
		sourcePath,
	).Scan(&hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return hash, err
}

// ListFiles lists all backed-up files with optional search filter.
func (d *DB) ListFiles(search string) ([]FileEntry, error) {
	query := `SELECT id, source_path, display_path FROM files`
	args := []interface{}{}
	if search != "" {
		query += ` WHERE display_path LIKE ?`
		args = append(args, "%"+search+"%")
	}
	query += ` ORDER BY display_path`
	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []FileEntry
	for rows.Next() {
		var f FileEntry
		if err := rows.Scan(&f.ID, &f.SourcePath, &f.DisplayPath); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// GetFileVersions returns all versions for a file ordered newest first.
func (d *DB) GetFileVersions(fileID int64) ([]FileVersion, error) {
	rows, err := d.conn.Query(
		`SELECT id, file_id, version_num, blob_id, size, hash, encrypted_at, job_id FROM file_versions WHERE file_id=? ORDER BY encrypted_at DESC`,
		fileID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var versions []FileVersion
	for rows.Next() {
		var v FileVersion
		var encStr string
		if err := rows.Scan(&v.ID, &v.FileID, &v.VersionNum, &v.BlobID, &v.Size, &v.Hash, &encStr, &v.JobID); err != nil {
			return nil, err
		}
		v.EncryptedAt, _ = time.Parse(time.RFC3339, encStr)
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// GetFileByID returns a file entry by ID.
func (d *DB) GetFileByID(id int64) (*FileEntry, error) {
	var f FileEntry
	err := d.conn.QueryRow(`SELECT id, source_path, display_path FROM files WHERE id=?`, id).Scan(&f.ID, &f.SourcePath, &f.DisplayPath)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, errors.New("file not found")
	}
	return &f, err
}

// ListFilesByDisplayPrefix returns all files whose display_path starts with the given
// prefix, ordered by display_path. If prefix is empty, all files are returned.
func (d *DB) ListFilesByDisplayPrefix(prefix string) ([]FileEntry, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if prefix == "" {
		rows, err = d.conn.Query(`SELECT id, source_path, display_path FROM files ORDER BY display_path`)
	} else {
		rows, err = d.conn.Query(
			`SELECT id, source_path, display_path FROM files WHERE display_path LIKE ? ORDER BY display_path`,
			prefix+"%",
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []FileEntry
	for rows.Next() {
		var f FileEntry
		if err := rows.Scan(&f.ID, &f.SourcePath, &f.DisplayPath); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// CreateSchedule creates a new schedule.
func (d *DB) CreateSchedule(name, cronExpr string, sourceDirs []string) (*Schedule, error) {
	dirs := strings.Join(sourceDirs, "\n")
	now := time.Now().UTC().Format(time.RFC3339)
	res, err := d.conn.Exec(
		`INSERT INTO schedules (name, cron_expr, source_dirs, enabled, created_at) VALUES (?,?,?,1,?)`,
		name, cronExpr, dirs, now,
	)
	if err != nil {
		return nil, err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, err
	}
	return &Schedule{
		ID:         id,
		Name:       name,
		CronExpr:   cronExpr,
		SourceDirs: sourceDirs,
		Enabled:    true,
		CreatedAt:  time.Now().UTC(),
	}, nil
}

// ListSchedules returns all schedules.
func (d *DB) ListSchedules() ([]Schedule, error) {
	rows, err := d.conn.Query(
		`SELECT id, name, cron_expr, source_dirs, enabled, created_at, last_run_at FROM schedules ORDER BY id`,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanSchedules(rows)
}

func scanSchedules(rows *sql.Rows) ([]Schedule, error) {
	var schedules []Schedule
	for rows.Next() {
		var s Schedule
		var dirsStr, createdAtStr string
		var lastRunStr sql.NullString
		var enabledInt int
		if err := rows.Scan(&s.ID, &s.Name, &s.CronExpr, &dirsStr, &enabledInt, &createdAtStr, &lastRunStr); err != nil {
			return nil, err
		}
		s.Enabled = enabledInt != 0
		if dirsStr != "" {
			s.SourceDirs = strings.Split(dirsStr, "\n")
		}
		s.CreatedAt, _ = time.Parse(time.RFC3339, createdAtStr)
		if lastRunStr.Valid {
			t, _ := time.Parse(time.RFC3339, lastRunStr.String)
			s.LastRunAt = &t
		}
		schedules = append(schedules, s)
	}
	return schedules, rows.Err()
}

// UpdateSchedule updates a schedule by ID.
func (d *DB) UpdateSchedule(id int64, name, cronExpr string, sourceDirs []string, enabled bool) error {
	dirs := strings.Join(sourceDirs, "\n")
	enabledInt := 0
	if enabled {
		enabledInt = 1
	}
	_, err := d.conn.Exec(
		`UPDATE schedules SET name=?, cron_expr=?, source_dirs=?, enabled=? WHERE id=?`,
		name, cronExpr, dirs, enabledInt, id,
	)
	return err
}

// DeleteSchedule removes a schedule.
func (d *DB) DeleteSchedule(id int64) error {
	_, err := d.conn.Exec(`DELETE FROM schedules WHERE id=?`, id)
	return err
}

// UpdateScheduleLastRun updates the last_run_at timestamp for a schedule.
func (d *DB) UpdateScheduleLastRun(id int64) error {
	_, err := d.conn.Exec(
		`UPDATE schedules SET last_run_at=? WHERE id=?`,
		time.Now().UTC().Format(time.RFC3339), id,
	)
	return err
}

// ListAllBlobIDs returns the blob ID of every file version currently in the
// database. This is used to enumerate blobs for remote deletion before wiping
// the local database.
func (d *DB) ListAllBlobIDs() ([]string, error) {
	return d.ListBlobIDsByDisplayPrefix("")
}

// ListBlobIDsByDisplayPrefix returns the blob IDs of all file versions for
// files whose display_path starts with the given prefix. If prefix is empty,
// all blob IDs are returned.
func (d *DB) ListBlobIDsByDisplayPrefix(prefix string) ([]string, error) {
	var (
		rows *sql.Rows
		err  error
	)
	if prefix == "" {
		rows, err = d.conn.Query(`SELECT blob_id FROM file_versions`)
	} else {
		rows, err = d.conn.Query(
			`SELECT fv.blob_id FROM file_versions fv
			 JOIN files f ON f.id = fv.file_id
			 WHERE f.display_path LIKE ?`,
			prefix+"%",
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

// DeleteAllFiles removes every file and file_version record from the database
// inside a single transaction.
func (d *DB) DeleteAllFiles() error {
	return d.DeleteFilesByDisplayPrefix("")
}

// DeleteFilesByDisplayPrefix removes file and file_version records whose
// display_path starts with the given prefix inside a single transaction. If
// prefix is empty, all records are deleted.
func (d *DB) DeleteFilesByDisplayPrefix(prefix string) error {
	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	if prefix == "" {
		if _, err = tx.Exec(`DELETE FROM file_versions`); err != nil {
			return err
		}
		if _, err = tx.Exec(`DELETE FROM files`); err != nil {
			return err
		}
	} else {
		if _, err = tx.Exec(
			`DELETE FROM file_versions WHERE file_id IN (SELECT id FROM files WHERE display_path LIKE ?)`,
			prefix+"%",
		); err != nil {
			return err
		}
		if _, err = tx.Exec(`DELETE FROM files WHERE display_path LIKE ?`, prefix+"%"); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// Backup creates a consistent copy of the database at destPath using SQLite's
// VACUUM INTO command. It is safe to call while the database is open and being
// written to (WAL mode ensures a consistent snapshot).
func (d *DB) Backup(destPath string) error {
	_, err := d.conn.Exec(`VACUUM INTO ?`, destPath)
	if err != nil {
		return fmt.Errorf("vacuum into %s: %w", destPath, err)
	}
	return nil
}
