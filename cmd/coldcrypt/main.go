package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"

	"github.com/seanmatheny/coldcrypt/internal/agent"
	"github.com/seanmatheny/coldcrypt/internal/config"
	"github.com/seanmatheny/coldcrypt/internal/db"
	"github.com/seanmatheny/coldcrypt/internal/dbdump"
	"github.com/seanmatheny/coldcrypt/internal/scheduler"
	"github.com/seanmatheny/coldcrypt/internal/web"

	"context"
)

// Version is set at build time via -ldflags "-X main.Version=<version>".
// It defaults to "dev" when not set.
var Version = "dev"

// setupLogging configures the standard logger to write to both stderr and a log
// file. If the log file cannot be opened, only stderr is used.
// The returned function should be called with defer to close the file.
func setupLogging() func() {
	const logPath = "/var/log/coldcrypt/coldcrypt.log"
	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0640)
	if err != nil {
		log.Printf("warning: could not open log file %s: %v (logging to stderr only)", logPath, err)
		return func() {}
	}
	log.SetOutput(io.MultiWriter(os.Stderr, f))
	log.Printf("logging to %s", logPath)
	return func() { _ = f.Close() }
}

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "init":
		cmdInit(os.Args[2:])
	case "serve":
		cmdServe(os.Args[2:])
	case "backup":
		cmdBackup(os.Args[2:])
	case "db-dump":
		cmdDBDump(os.Args[2:])
	case "db-restore":
		cmdDBRestore(os.Args[2:])
	case "change-password":
		cmdChangePassword(os.Args[2:])
	case "purge":
		cmdPurge(os.Args[2:])
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Fprintf(os.Stderr, `Coldcrypt - Encrypted Backup Manager

Usage:
  coldcrypt init <data-dir>             Initialize a new data directory
  coldcrypt serve [--config path] [--secrets-config path]       Start web server and scheduler
  coldcrypt backup [--config path] [--secrets-config path] [dirs...]  Run a one-off backup
  coldcrypt purge [--config path] [--secrets-config path] [--path <display-prefix>]  Permanently delete backed-up blobs
  coldcrypt db-dump [--config path] [--secrets-config path] --out <file> [--no-encrypt]  Dump a copy of the database
  coldcrypt db-restore [--config path] [--secrets-config path] --from <file>  Restore a database dump (plain or encrypted)
  coldcrypt change-password [--config path] [--secrets-config path]   Change the web UI password
`)
}

// ── init ───────────────────────────────────────────────────────────────────

func cmdInit(args []string) {
	if len(args) == 0 {
		fmt.Fprintln(os.Stderr, "usage: coldcrypt init <data-dir>")
		os.Exit(1)
	}
	dataDir := args[0]

	if err := os.MkdirAll(dataDir, 0700); err != nil {
		log.Fatalf("create data dir: %v", err)
	}

	salt, err := agent.GenerateSalt()
	if err != nil {
		log.Fatalf("generate salt: %v", err)
	}

	cfg := &config.Config{
		RemoteHost:     "your-backup-server.example.com",
		RemotePort:     22,
		RemoteUser:     "backup",
		RemoteKeyPath:  filepath.Join(os.Getenv("HOME"), ".ssh", "id_ed25519"),
		RemoteBasePath: "/backup/coldcrypt",
		SourceDirs:     []string{},
		WebPort:        8443,
		DataDir:        dataDir,
		KeySalt:        salt,
		Passphrase:     "change-me-to-a-strong-passphrase",
	}

	cfgPath := config.DefaultConfigPath(dataDir)
	secretsPath := config.DefaultSecretsPath(cfgPath)

	if err := config.SaveUI(cfg, cfgPath); err != nil {
		log.Fatalf("write config: %v", err)
	}
	if err := config.SaveSecrets(cfg, secretsPath); err != nil {
		log.Fatalf("write secrets: %v", err)
	}

	fmt.Printf(`Coldcrypt initialized!

Data directory : %s
Config file    : %s
Secrets file   : %s

Next steps:
  1. Edit %s (UI-editable settings):
     - Set remote_host, remote_user, remote_key_path
     - Set source_dirs to the directories you want to back up

  2. Edit %s (infrastructure/puppet-managed settings):
     - Replace the passphrase with a strong one (or use passphrase_file)
     - Optionally configure web_tls_cert/web_tls_key for HTTPS
     - Optionally configure web_port (default 8443)

  3. Set the web UI password:
       coldcrypt change-password --config %s

  4. Start the server:
       coldcrypt serve --config %s

`, dataDir, cfgPath, secretsPath, cfgPath, secretsPath, cfgPath, cfgPath)
}

// ── serve ──────────────────────────────────────────────────────────────────

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	secretsCfgPath := fs.String("secrets-config", "", "path to secrets.json (default: same directory as config.json)")
	_ = fs.Parse(args)

	closeLog := setupLogging()
	defer closeLog()

	cfg, resolvedPath, secretsPath := loadCombinedConfig(*cfgPath, *secretsCfgPath)

	database, err := db.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	a, err := agent.New(cfg, database)
	if err != nil {
		log.Fatalf("create agent: %v", err)
	}

	sched := scheduler.New(database, a, cfg)
	if err := sched.Start(); err != nil {
		log.Fatalf("start scheduler: %v", err)
	}
	defer sched.Stop()

	srv := web.New(cfg, resolvedPath, secretsPath, database, a, sched, Version)
	log.Printf("Starting Coldcrypt server on port %d", cfg.WebPort)
	if err := srv.Start(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// ── backup ─────────────────────────────────────────────────────────────────

func cmdBackup(args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	secretsCfgPath := fs.String("secrets-config", "", "path to secrets.json (default: same directory as config.json)")
	_ = fs.Parse(args)

	closeLog := setupLogging()
	defer closeLog()

	dirs := fs.Args()
	cfg, _, _ := loadCombinedConfig(*cfgPath, *secretsCfgPath)

	database, err := db.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	a, err := agent.New(cfg, database)
	if err != nil {
		log.Fatalf("create agent: %v", err)
	}

	if len(dirs) == 0 {
		dirs = cfg.SourceDirs
	}
	if len(dirs) == 0 {
		log.Fatalf("no source directories specified (pass dirs as arguments or set source_dirs in config)")
	}

	jobID, err := database.CreateJob()
	if err != nil {
		log.Fatalf("create job: %v", err)
	}

	log.Printf("Starting backup job %d", jobID)
	if err := a.Run(context.Background(), agent.BackupOptions{
		SourceDirs:     dirs,
		ExcludePaths:   cfg.ExcludePaths,
		ExcludeRegexes: cfg.ExcludeRegexes,
		JobID:          jobID,
	}); err != nil {
		log.Printf("backup failed: %v", err)
		_ = database.UpdateJob(jobID, "failed", 0, 0, err.Error())
		os.Exit(1)
	}
}

// ── purge ──────────────────────────────────────────────────────────────────

func cmdPurge(args []string) {
	fs := flag.NewFlagSet("purge", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	secretsCfgPath := fs.String("secrets-config", "", "path to secrets.json (default: same directory as config.json)")
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	purgePath := fs.String("path", "", "purge only files under this display path prefix (omit to purge everything)")
	_ = fs.Parse(args)

	closeLog := setupLogging()
	defer closeLog()

	cfg, _, _ := loadCombinedConfig(*cfgPath, *secretsCfgPath)

	if !*yes {
		if *purgePath != "" {
			fmt.Printf("WARNING: This will permanently delete all backed-up blobs under %q from the\n", *purgePath)
			fmt.Printf("remote server %s (path: %s) AND clear matching database records.\n", cfg.RemoteHost, cfg.RemoteBasePath)
		} else {
			fmt.Println("WARNING: This will permanently delete ALL backed-up blobs from the")
			fmt.Printf("remote server %s (path: %s) AND clear the local database.\n", cfg.RemoteHost, cfg.RemoteBasePath)
		}
		fmt.Println("This action CANNOT be undone.")
		fmt.Print("\nType DELETE ALL to confirm: ")
		line, _ := stdinReader.ReadString('\n')
		answer := strings.TrimRight(line, "\r\n")
		if answer != "DELETE ALL" {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
	}

	database, err := db.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	a, err := agent.New(cfg, database)
	if err != nil {
		log.Fatalf("create agent: %v", err)
	}

	if *purgePath != "" {
		fmt.Printf("Purging backed-up blobs under %q…\n", *purgePath)
	} else {
		fmt.Println("Purging all backed-up blobs…")
	}
	if err := a.PurgeByPrefix(context.Background(), *purgePath); err != nil {
		log.Fatalf("purge failed: %v", err)
	}
	if *purgePath != "" {
		fmt.Printf("Backups under %q have been purged.\n", *purgePath)
	} else {
		fmt.Println("All backups have been purged.")
	}
}

// ── db-dump ────────────────────────────────────────────────────────────────

func cmdDBDump(args []string) {
	fs := flag.NewFlagSet("db-dump", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	secretsCfgPath := fs.String("secrets-config", "", "path to secrets.json (default: same directory as config.json)")
	outPath := fs.String("out", "", "destination file for the database copy (required)")
	noEncrypt := fs.Bool("no-encrypt", false, "write plaintext dump output")
	_ = fs.Parse(args)

	if *outPath == "" {
		fmt.Fprintln(os.Stderr, "usage: coldcrypt db-dump --config <path> --out <file> [--no-encrypt]")
		os.Exit(1)
	}
	useEncryption := !*noEncrypt

	cfg, _, _ := loadCombinedConfig(*cfgPath, *secretsCfgPath)

	database, err := db.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	if !useEncryption {
		if err := database.Backup(*outPath); err != nil {
			log.Fatalf("db-dump: %v", err)
		}
		fmt.Printf("Database backed up to: %s\n", *outPath)
		return
	}

	passphrase, err := cfg.GetPassphrase()
	if err != nil {
		log.Fatalf("db-dump: get passphrase: %v", err)
	}

	tmp, err := os.CreateTemp("", "coldcrypt-dbdump-*.db")
	if err != nil {
		log.Fatalf("db-dump: create temp file: %v", err)
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	if err := database.Backup(tmpPath); err != nil {
		log.Fatalf("db-dump: %v", err)
	}

	src, err := os.Open(tmpPath)
	if err != nil {
		log.Fatalf("db-dump: open temp dump: %v", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(*outPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		log.Fatalf("db-dump: open destination: %v", err)
	}
	defer dst.Close()

	if err := dbdump.EncryptOpenSSLAES256CBC(passphrase, src, dst); err != nil {
		log.Fatalf("db-dump: encrypt output: %v", err)
	}
	if err := dst.Sync(); err != nil {
		log.Fatalf("db-dump: sync destination: %v", err)
	}
	fmt.Printf("Encrypted database backup written to: %s\n", *outPath)
}

// ── db-restore ─────────────────────────────────────────────────────────────

func cmdDBRestore(args []string) {
	fs := flag.NewFlagSet("db-restore", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	secretsCfgPath := fs.String("secrets-config", "", "path to secrets.json (default: same directory as config.json)")
	fromPath := fs.String("from", "", "path to the database dump to restore (required)")
	yes := fs.Bool("yes", false, "skip confirmation prompt")
	_ = fs.Parse(args)

	if *fromPath == "" {
		fmt.Fprintln(os.Stderr, "usage: coldcrypt db-restore --config <path> --from <dump-file>")
		os.Exit(1)
	}

	if _, err := os.Stat(*fromPath); err != nil {
		log.Fatalf("dump file not found: %v", err)
	}

	cfg, _, _ := loadCombinedConfig(*cfgPath, *secretsCfgPath)
	destPath := filepath.Join(cfg.DataDir, "coldcrypt.db")
	restorePath := *fromPath

	encrypted, err := isOpenSSLEncryptedDump(*fromPath)
	if err != nil {
		log.Fatalf("db-restore: inspect source dump: %v", err)
	}
	if encrypted {
		passphrase, err := cfg.GetPassphrase()
		if err != nil {
			log.Fatalf("db-restore: get passphrase: %v", err)
		}
		tmp, err := os.CreateTemp("", "coldcrypt-dbrestore-*.db")
		if err != nil {
			log.Fatalf("db-restore: create temp file: %v", err)
		}
		tmpPath := tmp.Name()
		_ = tmp.Close()
		defer os.Remove(tmpPath)

		if err := decryptDumpFile(*fromPath, tmpPath, passphrase); err != nil {
			log.Fatalf("db-restore: decrypt dump: %v", err)
		}
		restorePath = tmpPath
	}

	if !*yes {
		fmt.Printf("WARNING: This will overwrite %s with %s.\n", destPath, *fromPath)
		fmt.Print("Ensure the server is stopped before proceeding. Continue? [y/N] ")
		var answer string
		_, _ = fmt.Fscanln(stdinReader, &answer)
		if strings.ToLower(strings.TrimSpace(answer)) != "y" {
			fmt.Println("Aborted.")
			os.Exit(0)
		}
	}

	if err := copyFile(restorePath, destPath); err != nil {
		log.Fatalf("db-restore: %v", err)
	}

	// Remove stale WAL and SHM files left over from the previous database.
	for _, ext := range []string{"-wal", "-shm"} {
		_ = os.Remove(destPath + ext)
	}

	fmt.Printf("Database restored from %s to %s\n", *fromPath, destPath)
}

func isOpenSSLEncryptedDump(path string) (bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	header := make([]byte, 8)
	n, err := io.ReadFull(f, header)
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return false, nil
		}
		return false, err
	}
	return n == 8 && bytes.Equal(header, []byte(dbdump.OpenSSLSaltedPrefix)), nil
}

func decryptDumpFile(srcPath, dstPath, passphrase string) error {
	src, err := os.Open(srcPath)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	defer dst.Close()

	if err := dbdump.DecryptOpenSSLAES256CBC(passphrase, src, dst); err != nil {
		return err
	}
	return dst.Sync()
}

// copyFile copies the file at src to dst, creating or truncating dst.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("open source: %w", err)
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("open destination: %w", err)
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return fmt.Errorf("copy: %w", err)
	}
	return out.Sync()
}

func cmdChangePassword(args []string) {
	fs := flag.NewFlagSet("change-password", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	secretsCfgPath := fs.String("secrets-config", "", "path to secrets.json (default: same directory as config.json)")
	_ = fs.Parse(args)

	cfg, _, secretsPath := loadCombinedConfig(*cfgPath, *secretsCfgPath)

	password := promptPassword("New web UI password: ")
	confirm := promptPassword("Confirm password: ")

	if password != confirm {
		fmt.Fprintln(os.Stderr, "passwords do not match")
		os.Exit(1)
	}
	if password == "" {
		fmt.Fprintln(os.Stderr, "password cannot be empty")
		os.Exit(1)
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("hash password: %v", err)
	}

	cfg.WebPasswordHash = string(hash)
	if err := config.SaveSecrets(cfg, secretsPath); err != nil {
		log.Fatalf("save secrets: %v", err)
	}
	fmt.Println("Password updated successfully.")
}

// ── helpers ────────────────────────────────────────────────────────────────

// loadCombinedConfig loads config.json and, if present, secrets.json (or the
// path given by secretsCfgPath). Returns the merged Config, the resolved
// config.json path, and the resolved secrets.json path.
func loadCombinedConfig(cfgPath, secretsCfgPath string) (*config.Config, string, string) {
	if cfgPath == "" {
		// Try a few standard locations
		candidates := []string{
			"config.json",
			filepath.Join(os.Getenv("HOME"), ".coldcrypt", "config.json"),
			"/etc/coldcrypt/config.json",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				cfgPath = c
				break
			}
		}
	}
	if cfgPath == "" {
		log.Fatalf("config file not found; pass --config <path> or run 'coldcrypt init'")
	}
	absPath, err := filepath.Abs(cfgPath)
	if err != nil {
		absPath = cfgPath
	}
	if secretsCfgPath == "" {
		secretsCfgPath = config.DefaultSecretsPath(absPath)
	} else {
		sp, err := filepath.Abs(secretsCfgPath)
		if err == nil {
			secretsCfgPath = sp
		}
	}
	if _, err := os.Stat(secretsCfgPath); os.IsNotExist(err) {
		log.Printf("note: secrets config %s not found; infrastructure fields will be read from config.json", secretsCfgPath)
	}
	cfg, err := config.LoadCombined(absPath, secretsCfgPath)
	if err != nil {
		log.Fatalf("load config %s: %v", absPath, err)
	}
	return cfg, absPath, secretsCfgPath
}

// stdinReader is a shared buffered reader for non-terminal stdin input.
var stdinReader = bufio.NewReader(os.Stdin)

// promptPassword reads a password from the terminal (no echo).
func promptPassword(prompt string) string {
	fmt.Print(prompt)
	// Try terminal-aware password reading first
	if term.IsTerminal(int(syscall.Stdin)) {
		pw, err := term.ReadPassword(int(syscall.Stdin))
		fmt.Println()
		if err != nil {
			log.Fatalf("read password: %v", err)
		}
		return strings.TrimRight(string(pw), "\r\n")
	}
	// Fall back to shared buffered reader (e.g., piped input in tests)
	pw, _ := stdinReader.ReadString('\n')
	return strings.TrimRight(pw, "\r\n")
}
