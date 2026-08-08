package db

import (
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
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
	JobType          string
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
	Size        int64
	MtimeNS     int64
}

// FileLifecycleEntry includes deletion-state metadata for a tracked file.
type FileLifecycleEntry struct {
	ID         int64
	SourcePath string
	DeletedAt  *time.Time
}

// FileVersion represents a single version of a backed-up file.
type FileVersion struct {
	ID          int64
	FileID      int64
	VersionNum  int
	BlobID      string
	Size        int64
	MtimeNS     int64
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
    display_path TEXT NOT NULL,
    deleted_at DATETIME
);

CREATE INDEX IF NOT EXISTS idx_files_display_path ON files(display_path);

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
	// Keep all temp tables and sort files in memory so that index creation
	// during schema migration works in hardened systemd environments where
	// the temp directory may not be accessible (ProtectSystem=strict).
	if _, err := conn.Exec("PRAGMA temp_store = 2"); err != nil {
		return nil, fmt.Errorf("temp_store: %w", err)
	}
	if _, err := conn.Exec(schema); err != nil {
		return nil, fmt.Errorf("create schema: %w", err)
	}
	// Add mtime_ns column to existing databases that pre-date this column.
	// Use PRAGMA table_info rather than catching ALTER TABLE errors so the
	// migration is robust across SQLite driver versions.
	if err := addColumnIfMissing(conn, "file_versions", "mtime_ns",
		`ALTER TABLE file_versions ADD COLUMN mtime_ns INTEGER NOT NULL DEFAULT 0`); err != nil {
		return nil, err
	}
	// Add deleted_at column to existing databases that pre-date source-deletion
	// retention tracking.
	if err := addColumnIfMissing(conn, "files", "deleted_at",
		`ALTER TABLE files ADD COLUMN deleted_at DATETIME`); err != nil {
		return nil, err
	}
	// Add job_type column to existing databases so backup and restore jobs can
	// be distinguished in history.
	if err := addColumnIfMissing(conn, "backup_jobs", "job_type",
		`ALTER TABLE backup_jobs ADD COLUMN job_type TEXT NOT NULL DEFAULT 'backup'`); err != nil {
		return nil, err
	}
	return &DB{conn: conn}, nil
}

// Close closes the database connection.
func (d *DB) Close() error {
	return d.conn.Close()
}

// addColumnIfMissing adds the given column to a table only when it is not
// already present. It uses PRAGMA table_info to check for the column, which is
// more reliable than catching driver-specific error message strings.
func addColumnIfMissing(conn *sql.DB, table, column, alterSQL string) error {
	rows, err := conn.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return fmt.Errorf("table_info %s: %w", table, err)
	}
	defer rows.Close()
	for rows.Next() {
		var cid int
		var name, colType string
		var notNull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notNull, &dflt, &pk); err != nil {
			return fmt.Errorf("scan table_info %s: %w", table, err)
		}
		if name == column {
			return nil // column already exists
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("table_info rows %s: %w", table, err)
	}
	if _, err := conn.Exec(alterSQL); err != nil {
		return fmt.Errorf("add column %s.%s: %w", table, column, err)
	}
	return nil
}

// CreateJob creates a new backup job and returns its ID.
func (d *DB) CreateJob() (int64, error) {
	return d.CreateJobWithType("backup")
}

// CreateJobWithType creates a new job with the provided job type.
func (d *DB) CreateJobWithType(jobType string) (int64, error) {
	if strings.TrimSpace(jobType) == "" {
		jobType = "backup"
	}
	res, err := d.conn.Exec(
		`INSERT INTO backup_jobs (job_type, started_at, status) VALUES (?, ?, 'running')`,
		jobType, time.Now().UTC().Format(time.RFC3339),
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
		`SELECT id, COALESCE(job_type,'backup'), started_at, completed_at, status, files_processed, bytes_transferred, COALESCE(error_message,'') FROM backup_jobs ORDER BY started_at DESC LIMIT ?`,
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
		`SELECT id, COALESCE(job_type,'backup'), started_at, completed_at, status, files_processed, bytes_transferred, COALESCE(error_message,'') FROM backup_jobs WHERE id=?`,
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
		if err := rows.Scan(&j.ID, &j.JobType, &startedAtStr, &completedAtStr, &j.Status, &j.FilesProcessed, &j.BytesTransferred, &j.ErrorMessage); err != nil {
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
func (d *DB) UpsertFileVersion(sourcePath, displayPath, blobID, hash string, size, mtimeNS, jobID int64) (oldBlobID string, err error) {
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
	} else {
		// Clear deleted_at when a previously-missing source file reappears and is
		// being versioned again.
		_, err = tx.Exec(`UPDATE files SET display_path=?, deleted_at=NULL WHERE id=?`, displayPath, fileID)
		if err != nil {
			return "", err
		}
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
			`INSERT INTO file_versions (file_id, version_num, blob_id, size, hash, mtime_ns, encrypted_at, job_id) VALUES (?,?,?,?,?,?,?,?)`,
			fileID, nextVer, blobID, size, hash, mtimeNS, now, jobID,
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
			`INSERT INTO file_versions (file_id, version_num, blob_id, size, hash, mtime_ns, encrypted_at, job_id) VALUES (?,?,?,?,?,?,?,?)`,
			fileID, nextVer, blobID, size, hash, mtimeNS, now, jobID,
		)
		if err != nil {
			return "", err
		}
	}

	err = tx.Commit()
	return oldBlobID, err
}

// GetLatestVersionInfo returns the hash, size, and mtime (nanoseconds) of the
// most recent version for a source path, or zero values if not found.
func (d *DB) GetLatestVersionInfo(sourcePath string) (hash string, size int64, mtimeNS int64, err error) {
	err = d.conn.QueryRow(
		`SELECT fv.hash, fv.size, fv.mtime_ns FROM file_versions fv
		 JOIN files f ON f.id = fv.file_id
		 WHERE f.source_path=?
		 ORDER BY fv.encrypted_at DESC LIMIT 1`,
		sourcePath,
	).Scan(&hash, &size, &mtimeNS)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, 0, nil
	}
	return hash, size, mtimeNS, err
}

// UpdateLatestVersionMtime updates the mtime_ns stored for the most recent
// version of a file. This is called when a file's content is confirmed
// unchanged (hash matches) but its mtime/size metadata has drifted, so future
// backup runs can skip the SHA-256 read via the stat pre-check.
func (d *DB) UpdateLatestVersionMtime(sourcePath string, mtimeNS int64) error {
	_, err := d.conn.Exec(
		`UPDATE file_versions SET mtime_ns=?
		 WHERE id = (
		     SELECT fv.id FROM file_versions fv
		     JOIN files f ON f.id = fv.file_id
		     WHERE f.source_path=?
		     ORDER BY fv.encrypted_at DESC LIMIT 1
		 )`,
		mtimeNS, sourcePath,
	)
	return err
}

// CountFiles returns the total number of distinct backed-up files.
func (d *DB) CountFiles() (int64, error) {
	var count int64
	err := d.conn.QueryRow(`SELECT COUNT(*) FROM files`).Scan(&count)
	return count, err
}

// ListFiles lists backed-up files with an optional search filter.
// When limit > 0, at most limit+1 rows are fetched so the caller can detect
// truncation (len(result) > limit) without a separate COUNT query.
func (d *DB) ListFiles(search string, limit int) ([]FileEntry, error) {
	query := `SELECT f.id, f.source_path, f.display_path,
		COALESCE((SELECT fv.size FROM file_versions fv WHERE fv.file_id=f.id ORDER BY fv.encrypted_at DESC LIMIT 1), 0) AS latest_size,
		COALESCE((SELECT fv.mtime_ns FROM file_versions fv WHERE fv.file_id=f.id ORDER BY fv.encrypted_at DESC LIMIT 1), 0) AS latest_mtime_ns
		FROM files f`
	// Exclude files awaiting deleted-source retention purge so the Files tab
	// (both tree and flat search) only shows content currently present in the source.
	query += ` WHERE f.deleted_at IS NULL`
	args := []interface{}{}
	if search != "" {
		query += ` AND display_path LIKE ?`
		args = append(args, "%"+search+"%")
	}
	query += ` ORDER BY display_path`
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit+1)
	}
	rows, err := d.conn.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []FileEntry
	for rows.Next() {
		var f FileEntry
		if err := rows.Scan(&f.ID, &f.SourcePath, &f.DisplayPath, &f.Size, &f.MtimeNS); err != nil {
			return nil, err
		}
		files = append(files, f)
	}
	return files, rows.Err()
}

// GetFileVersions returns all versions for a file ordered newest first.
func (d *DB) GetFileVersions(fileID int64) ([]FileVersion, error) {
	rows, err := d.conn.Query(
		`SELECT id, file_id, version_num, blob_id, size, mtime_ns, hash, encrypted_at, job_id FROM file_versions WHERE file_id=? ORDER BY encrypted_at DESC`,
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
		if err := rows.Scan(&v.ID, &v.FileID, &v.VersionNum, &v.BlobID, &v.Size, &v.MtimeNS, &v.Hash, &encStr, &v.JobID); err != nil {
			return nil, err
		}
		v.EncryptedAt, _ = time.Parse(time.RFC3339, encStr)
		versions = append(versions, v)
	}
	return versions, rows.Err()
}

// DeleteFileVersion removes one version row by (file_id, version_num) and
// deletes the parent file row if it no longer has any versions. It returns the
// removed blob ID.
func (d *DB) DeleteFileVersion(fileID int64, versionNum int) (string, error) {
	tx, err := d.conn.Begin()
	if err != nil {
		return "", err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()

	var versionID int64
	var blobID string
	err = tx.QueryRow(
		`SELECT id, blob_id FROM file_versions WHERE file_id=? AND version_num=?`,
		fileID, versionNum,
	).Scan(&versionID, &blobID)
	if errors.Is(err, sql.ErrNoRows) {
		return "", errors.New("version not found")
	}
	if err != nil {
		return "", err
	}

	if _, err = tx.Exec(`DELETE FROM file_versions WHERE id=?`, versionID); err != nil {
		return "", err
	}
	if _, err = tx.Exec(
		`DELETE FROM files WHERE id=? AND NOT EXISTS (SELECT 1 FROM file_versions WHERE file_id=?)`,
		fileID, fileID,
	); err != nil {
		return "", err
	}
	if err = tx.Commit(); err != nil {
		return "", err
	}
	return blobID, nil
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
		rows, qErr := tx.Query(`SELECT id FROM files WHERE display_path LIKE ?`, prefix+"%")
		if qErr != nil {
			return qErr
		}
		var fileIDs []int64
		for rows.Next() {
			var id int64
			if scanErr := rows.Scan(&id); scanErr != nil {
				_ = rows.Close()
				return scanErr
			}
			fileIDs = append(fileIDs, id)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			_ = rows.Close()
			return rowsErr
		}
		if closeErr := rows.Close(); closeErr != nil {
			return closeErr
		}
		if len(fileIDs) == 0 {
			return tx.Commit()
		}

		ph := make([]string, len(fileIDs))
		args := make([]interface{}, len(fileIDs))
		for i, id := range fileIDs {
			ph[i] = "?"
			args[i] = id
		}
		in := strings.Join(ph, ",")

		if _, err = tx.Exec(fmt.Sprintf(`DELETE FROM file_versions WHERE file_id IN (%s)`, in), args...); err != nil {
			return err
		}
		if _, err = tx.Exec(fmt.Sprintf(`DELETE FROM files WHERE id IN (%s)`, in), args...); err != nil {
			return err
		}
	}

	return tx.Commit()
}

// DirChild represents an immediate child (file or sub-directory) at a given display-path prefix.
type DirChild struct {
	// Name is the directory segment name (for dirs) or basename (for files).
	Name     string
	IsDir    bool
	FileID   int64  // only set when IsDir is false
	FullPath string // complete display_path; only set when IsDir is false
	Size     int64  // latest backed-up size; only set when IsDir is false
	MtimeNS  int64  // latest source mtime (ns); only set when IsDir is false
}

// ListDirectChildren returns the immediate children (files and sub-directory names) beneath
// the given display-path prefix. Use an empty string for root-level children.
// A non-empty prefix must end with "/".
// Results are sorted: directories first (alphabetically), then files (alphabetically).
func (d *DB) ListDirectChildren(prefix string) ([]DirChild, error) {
	var (
		rows *sql.Rows
		err  error
	)
	// Files awaiting deleted-source retention purge (deleted_at IS NOT NULL) are
	// excluded so the tree reflects only content currently present in the source.
	// Because directory nodes are derived from file paths, a directory whose files
	// have all been deleted no longer appears — empty directories drop out of the tree.
	if prefix == "" {
		rows, err = d.conn.Query(
			`SELECT f.id, f.display_path,
			        (SELECT fv.size FROM file_versions fv WHERE fv.file_id=f.id ORDER BY fv.encrypted_at DESC LIMIT 1) AS latest_size,
			        (SELECT fv.mtime_ns FROM file_versions fv WHERE fv.file_id=f.id ORDER BY fv.encrypted_at DESC LIMIT 1) AS latest_mtime_ns
			   FROM files f
			  WHERE f.deleted_at IS NULL
			  ORDER BY f.display_path`,
		)
	} else {
		rows, err = d.conn.Query(
			`SELECT f.id, f.display_path,
			        (SELECT fv.size FROM file_versions fv WHERE fv.file_id=f.id ORDER BY fv.encrypted_at DESC LIMIT 1) AS latest_size,
			        (SELECT fv.mtime_ns FROM file_versions fv WHERE fv.file_id=f.id ORDER BY fv.encrypted_at DESC LIMIT 1) AS latest_mtime_ns
			   FROM files f
			  WHERE f.display_path LIKE ? AND f.deleted_at IS NULL
			  ORDER BY f.display_path`,
			prefix+"%",
		)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	seenDirs := make(map[string]struct{})
	var children []DirChild
	for rows.Next() {
		var id int64
		var dp string
		var latestSize sql.NullInt64
		var latestMtimeNS sql.NullInt64
		if err := rows.Scan(&id, &dp, &latestSize, &latestMtimeNS); err != nil {
			return nil, err
		}
		rest := dp[len(prefix):]
		if rest == "" {
			continue
		}
		if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
			dirName := rest[:slashIdx]
			if dirName != "" {
				if _, seen := seenDirs[dirName]; !seen {
					seenDirs[dirName] = struct{}{}
					children = append(children, DirChild{Name: dirName, IsDir: true})
				}
			}
		} else {
			child := DirChild{Name: rest, IsDir: false, FileID: id, FullPath: dp}
			if latestSize.Valid {
				child.Size = latestSize.Int64
			}
			if latestMtimeNS.Valid {
				child.MtimeNS = latestMtimeNS.Int64
			}
			children = append(children, child)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	sort.Slice(children, func(i, j int) bool {
		if children[i].IsDir != children[j].IsDir {
			return children[i].IsDir // directories before files
		}
		return children[i].Name < children[j].Name
	})
	return children, nil
}

// CountDirectChildren returns the number of immediate children beneath the given prefix.
// This is used to show whether a directory node is expandable in the UI.
func (d *DB) CountDirectChildren(prefix string) (int64, error) {
	children, err := d.ListDirectChildren(prefix)
	if err != nil {
		return 0, err
	}
	return int64(len(children)), nil
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

// ListFileLifecycleEntries returns all tracked files and their source-deletion
// marker timestamps.
func (d *DB) ListFileLifecycleEntries() ([]FileLifecycleEntry, error) {
	rows, err := d.conn.Query(`SELECT id, source_path, deleted_at FROM files`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []FileLifecycleEntry
	for rows.Next() {
		var e FileLifecycleEntry
		var deletedAtStr sql.NullString
		if err := rows.Scan(&e.ID, &e.SourcePath, &deletedAtStr); err != nil {
			return nil, err
		}
		if deletedAtStr.Valid {
			if t, err := time.Parse(time.RFC3339, deletedAtStr.String); err == nil {
				e.DeletedAt = &t
			}
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// MarkFileDeletedIfUnset records when a source file first disappeared.
func (d *DB) MarkFileDeletedIfUnset(sourcePath string, deletedAt time.Time) error {
	_, err := d.conn.Exec(
		`UPDATE files SET deleted_at=? WHERE source_path=? AND deleted_at IS NULL`,
		deletedAt.UTC().Format(time.RFC3339), sourcePath,
	)
	return err
}

// ClearFileDeleted clears a file's deletion marker when it reappears.
func (d *DB) ClearFileDeleted(sourcePath string) error {
	_, err := d.conn.Exec(`UPDATE files SET deleted_at=NULL WHERE source_path=?`, sourcePath)
	return err
}

// ListBlobIDsByFileIDs returns all version blob IDs for the provided file IDs.
func (d *DB) ListBlobIDsByFileIDs(fileIDs []int64) ([]string, error) {
	if len(fileIDs) == 0 {
		return nil, nil
	}
	ph := make([]string, len(fileIDs))
	args := make([]interface{}, len(fileIDs))
	for i, id := range fileIDs {
		ph[i] = "?"
		args[i] = id
	}
	rows, err := d.conn.Query(
		fmt.Sprintf(`SELECT blob_id FROM file_versions WHERE file_id IN (%s)`, strings.Join(ph, ",")),
		args...,
	)
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

// DeleteFilesByIDs removes file/version rows for the provided file IDs.
func (d *DB) DeleteFilesByIDs(fileIDs []int64) error {
	if len(fileIDs) == 0 {
		return nil
	}
	ph := make([]string, len(fileIDs))
	args := make([]interface{}, len(fileIDs))
	for i, id := range fileIDs {
		ph[i] = "?"
		args[i] = id
	}
	tx, err := d.conn.Begin()
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = tx.Rollback()
		}
	}()
	in := strings.Join(ph, ",")
	if _, err = tx.Exec(fmt.Sprintf(`DELETE FROM file_versions WHERE file_id IN (%s)`, in), args...); err != nil {
		return err
	}
	if _, err = tx.Exec(fmt.Sprintf(`DELETE FROM files WHERE id IN (%s)`, in), args...); err != nil {
		return err
	}
	return tx.Commit()
}
