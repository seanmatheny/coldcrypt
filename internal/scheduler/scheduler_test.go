package scheduler

import (
	"testing"
	"time"

	"github.com/seanmatheny/coldcrypt/internal/agent"
	"github.com/seanmatheny/coldcrypt/internal/config"
	"github.com/seanmatheny/coldcrypt/internal/db"
)

func newTestScheduler(t *testing.T, cfg *config.Config) (*Scheduler, *db.DB) {
	t.Helper()
	dir := t.TempDir()
	database, err := db.New(dir)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	salt, err := agent.GenerateSalt()
	if err != nil {
		t.Fatalf("generate salt: %v", err)
	}
	cfg.Passphrase = "test-passphrase"
	cfg.KeySalt = salt
	cfg.DataDir = dir

	a, err := agent.New(cfg, database)
	if err != nil {
		t.Fatalf("create agent: %v", err)
	}
	return New(database, a, cfg), database
}

func TestValidateCronExpr(t *testing.T) {
	valid := []string{"0 3 * * 0", "*/15 * * * *", "30 2 1 * *", "@daily", "@every 1h"}
	for _, expr := range valid {
		if err := ValidateCronExpr(expr); err != nil {
			t.Errorf("ValidateCronExpr(%q) = %v, want nil", expr, err)
		}
	}
	invalid := []string{
		"0 0 3 * * 0", // six fields (seconds) — not accepted by the standard parser
		"0 3 * * 7",   // day-of-week 7 — robfig/cron only accepts 0-6
		"61 * * * *",  // minute out of range
		"not a cron",
		"",
	}
	for _, expr := range invalid {
		if err := ValidateCronExpr(expr); err == nil {
			t.Errorf("ValidateCronExpr(%q) = nil, want error", expr)
		}
	}
}

func TestIntegrityScanScheduleRegistered(t *testing.T) {
	cfg := &config.Config{
		IntegrityScanEnabled:  true,
		IntegrityScanCronExpr: "0 3 * * 0",
	}
	s, _ := newTestScheduler(t, cfg)
	if err := s.Start(); err != nil {
		t.Fatalf("start scheduler: %v", err)
	}
	defer s.Stop()

	if s.scanID == 0 {
		t.Fatal("integrity scan schedule was not registered with cron")
	}
}

func TestIntegrityScanScheduleFiresAndCreatesJob(t *testing.T) {
	cfg := &config.Config{
		IntegrityScanEnabled:  true,
		IntegrityScanCronExpr: "@every 1s",
	}
	s, database := newTestScheduler(t, cfg)
	if err := s.Start(); err != nil {
		t.Fatalf("start scheduler: %v", err)
	}
	defer s.Stop()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		jobs, err := database.ListJobs(10)
		if err != nil {
			t.Fatalf("list jobs: %v", err)
		}
		for _, j := range jobs {
			if j.JobType == "scan" {
				return // scheduled scan created a job — success
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("scheduled integrity scan never created a job in the jobs table")
}

func TestIntegrityScanScheduleAfterReload(t *testing.T) {
	cfg := &config.Config{
		IntegrityScanEnabled:  false,
		IntegrityScanCronExpr: "",
	}
	s, _ := newTestScheduler(t, cfg)
	if err := s.Start(); err != nil {
		t.Fatalf("start scheduler: %v", err)
	}
	defer s.Stop()

	if s.scanID != 0 {
		t.Fatal("scan schedule should not be registered when disabled")
	}

	// Simulate the settings save path: mutate config, then Reload.
	cfg.IntegrityScanEnabled = true
	cfg.IntegrityScanCronExpr = "0 3 * * 0"
	if err := s.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if s.scanID == 0 {
		t.Fatal("integrity scan schedule was not registered after config reload")
	}
}
