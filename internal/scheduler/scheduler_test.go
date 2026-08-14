package scheduler

import (
	"testing"
	"time"

	"github.com/seanmatheny/coldcrypt/internal/agent"
	"github.com/seanmatheny/coldcrypt/internal/config"
	"github.com/seanmatheny/coldcrypt/internal/db"
)

func newTestScheduler(t *testing.T) (*Scheduler, *db.DB) {
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
	cfg := &config.Config{
		Passphrase: "test-passphrase",
		KeySalt:    salt,
		DataDir:    dir,
	}

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
	s, database := newTestScheduler(t)
	sched, err := database.CreateSchedule(db.Schedule{
		Name:                  "nightly",
		CronExpr:              "0 2 * * *",
		SourceDirs:            []string{"/data"},
		Enabled:               true,
		IntegrityScanEnabled:  true,
		IntegrityScanCronExpr: "0 3 * * 0",
	})
	if err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start scheduler: %v", err)
	}
	defer s.Stop()

	if _, ok := s.scanIDs[sched.ID]; !ok {
		t.Fatal("integrity scan schedule was not registered with cron")
	}
}

func TestIntegrityScanScheduleFiresAndCreatesJob(t *testing.T) {
	s, database := newTestScheduler(t)
	if _, err := database.CreateSchedule(db.Schedule{
		Name:                  "nightly",
		CronExpr:              "0 2 * * *",
		SourceDirs:            []string{"/data"},
		Enabled:               true,
		IntegrityScanEnabled:  true,
		IntegrityScanCronExpr: "@every 1s",
	}); err != nil {
		t.Fatalf("create schedule: %v", err)
	}
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
	s, database := newTestScheduler(t)
	sched, err := database.CreateSchedule(db.Schedule{
		Name:       "nightly",
		CronExpr:   "0 2 * * *",
		SourceDirs: []string{"/data"},
		Enabled:    true,
	})
	if err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	if err := s.Start(); err != nil {
		t.Fatalf("start scheduler: %v", err)
	}
	defer s.Stop()

	if len(s.scanIDs) != 0 {
		t.Fatal("scan schedule should not be registered when disabled")
	}

	// Simulate the schedule save path: update the schedule, then Reload.
	updated := *sched
	updated.IntegrityScanEnabled = true
	updated.IntegrityScanCronExpr = "0 3 * * 0"
	if err := database.UpdateSchedule(sched.ID, updated); err != nil {
		t.Fatalf("update schedule: %v", err)
	}
	if err := s.Reload(); err != nil {
		t.Fatalf("reload: %v", err)
	}
	if _, ok := s.scanIDs[sched.ID]; !ok {
		t.Fatal("integrity scan schedule was not registered after reload")
	}
}

func TestScheduleSettingsRoundTrip(t *testing.T) {
	_, database := newTestScheduler(t)
	in := db.Schedule{
		Name:                    "docs",
		CronExpr:                "0 2 * * *",
		SourceDirs:              []string{"/data/docs", "/data/photos"},
		Enabled:                 true,
		ExcludePaths:            []string{"/data/docs/tmp"},
		ExcludeRegexes:          []string{`\.log$`},
		DeletedRetentionEnabled: true,
		DeletedRetentionValue:   2,
		DeletedRetentionUnit:    "weeks",
		CompressionEnabled:      true,
		IntegrityScanEnabled:    true,
		IntegrityScanCronExpr:   "0 3 * * 0",
	}
	created, err := database.CreateSchedule(in)
	if err != nil {
		t.Fatalf("create schedule: %v", err)
	}
	got, err := database.GetSchedule(created.ID)
	if err != nil {
		t.Fatalf("get schedule: %v", err)
	}
	if got.ExcludePaths[0] != "/data/docs/tmp" || got.ExcludeRegexes[0] != `\.log$` {
		t.Errorf("excludes did not round-trip: %+v", got)
	}
	if !got.DeletedRetentionEnabled || got.DeletedRetentionValue != 2 || got.DeletedRetentionUnit != "weeks" {
		t.Errorf("retention did not round-trip: %+v", got)
	}
	if !got.CompressionEnabled || !got.IntegrityScanEnabled || got.IntegrityScanCronExpr != "0 3 * * 0" {
		t.Errorf("compression/scan did not round-trip: %+v", got)
	}
	if d, ok := got.DeletedRetentionDuration(); !ok || d != 2*7*24*time.Hour {
		t.Errorf("DeletedRetentionDuration = %v, %v; want 2 weeks, true", d, ok)
	}
}
