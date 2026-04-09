package main

import (
	"bufio"
	"flag"
	"fmt"
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
	"github.com/seanmatheny/coldcrypt/internal/scheduler"
	"github.com/seanmatheny/coldcrypt/internal/web"

	"context"
)

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
	case "change-password":
		cmdChangePassword(os.Args[2:])
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
  coldcrypt serve [--config path]       Start web server and scheduler
  coldcrypt backup [--config path] [dirs...]  Run a one-off backup
  coldcrypt change-password [--config path]   Change the web UI password
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
	if err := config.Save(cfg, cfgPath); err != nil {
		log.Fatalf("write config: %v", err)
	}

	fmt.Printf(`Coldcrypt initialized!

Data directory : %s
Config file    : %s

Next steps:
  1. Edit %s:
     - Set remote_host, remote_user, remote_key_path
     - Set source_dirs to the directories you want to back up
     - Replace the passphrase with a strong one (or use passphrase_file)
     - Optionally configure web_tls_cert/web_tls_key for HTTPS

  2. Set the web UI password:
       coldcrypt change-password --config %s

  3. Start the server:
       coldcrypt serve --config %s

`, dataDir, cfgPath, cfgPath, cfgPath, cfgPath)
}

// ── serve ──────────────────────────────────────────────────────────────────

func cmdServe(args []string) {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	_ = fs.Parse(args)

	cfg, resolvedPath := loadConfig(*cfgPath)

	database, err := db.New(cfg.DataDir)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer database.Close()

	a, err := agent.New(cfg, database)
	if err != nil {
		log.Fatalf("create agent: %v", err)
	}

	sched := scheduler.New(database, a)
	if err := sched.Start(); err != nil {
		log.Fatalf("start scheduler: %v", err)
	}
	defer sched.Stop()

	srv := web.New(cfg, resolvedPath, database, a, sched)
	log.Printf("Starting Coldcrypt server on port %d", cfg.WebPort)
	if err := srv.Start(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

// ── backup ─────────────────────────────────────────────────────────────────

func cmdBackup(args []string) {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	_ = fs.Parse(args)

	dirs := fs.Args()
	cfg, _ := loadConfig(*cfgPath)

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
		SourceDirs: dirs,
		JobID:      jobID,
	}); err != nil {
		log.Printf("backup failed: %v", err)
		_ = database.UpdateJob(jobID, "failed", 0, 0, err.Error())
		os.Exit(1)
	}
}

// ── change-password ────────────────────────────────────────────────────────

func cmdChangePassword(args []string) {
	fs := flag.NewFlagSet("change-password", flag.ExitOnError)
	cfgPath := fs.String("config", "", "path to config.json")
	_ = fs.Parse(args)

	cfg, resolvedPath := loadConfig(*cfgPath)

	password := promptPassword("New web UI password: ")
	confirm  := promptPassword("Confirm password: ")

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
	if err := config.Save(cfg, resolvedPath); err != nil {
		log.Fatalf("save config: %v", err)
	}
	fmt.Println("Password updated successfully.")
}

// ── helpers ────────────────────────────────────────────────────────────────

// loadConfig loads config from the given path or searches standard locations.
func loadConfig(cfgPath string) (*config.Config, string) {
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
	cfg, err := config.Load(absPath)
	if err != nil {
		log.Fatalf("load config %s: %v", absPath, err)
	}
	return cfg, absPath
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
