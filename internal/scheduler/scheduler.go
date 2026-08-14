package scheduler

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"

	cronv3 "github.com/robfig/cron/v3"
	"github.com/seanmatheny/coldcrypt/internal/agent"
	"github.com/seanmatheny/coldcrypt/internal/config"
	"github.com/seanmatheny/coldcrypt/internal/db"
	"github.com/seanmatheny/coldcrypt/internal/notify"
)

// Scheduler manages cron-based backup schedules.
type Scheduler struct {
	mu       sync.Mutex
	cron     *cronv3.Cron
	cfg      *config.Config
	db       *db.DB
	agent    *agent.Agent
	entryIDs map[int64]cronv3.EntryID
	scanIDs  map[int64]cronv3.EntryID // per-schedule integrity scan entries
}

// ValidateCronExpr checks expr against the same parser the scheduler uses,
// so that invalid expressions can be rejected at save time instead of failing
// silently when the schedule is loaded.
func ValidateCronExpr(expr string) error {
	_, err := cronv3.ParseStandard(expr)
	return err
}

// New creates a new Scheduler.
func New(database *db.DB, a *agent.Agent, cfg *config.Config) *Scheduler {
	return &Scheduler{
		cfg:      cfg,
		db:       database,
		agent:    a,
		entryIDs: make(map[int64]cronv3.EntryID),
		scanIDs:  make(map[int64]cronv3.EntryID),
	}
}

// Start starts the scheduler and loads all enabled schedules from the database.
func (s *Scheduler) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.cron = cronv3.New()
	if err := s.loadSchedules(); err != nil {
		return err
	}
	s.cron.Start()
	return nil
}

// Stop stops the scheduler gracefully.
func (s *Scheduler) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cron != nil {
		s.cron.Stop()
	}
}

// Reload reloads all schedules from the database.
// Call this after any CRUD operation on schedules.
func (s *Scheduler) Reload() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.cron == nil {
		return nil
	}

	// Stop and recreate the cron instance.
	s.cron.Stop()
	s.cron = cronv3.New()
	s.entryIDs = make(map[int64]cronv3.EntryID)
	s.scanIDs = make(map[int64]cronv3.EntryID)

	if err := s.loadSchedules(); err != nil {
		return err
	}
	s.cron.Start()
	return nil
}

// loadSchedules adds all enabled DB schedules to the cron instance.
// Caller must hold s.mu.
func (s *Scheduler) loadSchedules() error {
	schedules, err := s.db.ListSchedules()
	if err != nil {
		return fmt.Errorf("list schedules: %w", err)
	}

	for _, sched := range schedules {
		if !sched.Enabled {
			continue
		}
		sched := sched
		entryID, err := s.cron.AddFunc(sched.CronExpr, func() {
			s.runSchedule(sched)
		})
		if err != nil {
			log.Printf("scheduler: invalid cron expr for schedule %d (%s): %v", sched.ID, sched.CronExpr, err)
			continue
		}
		s.entryIDs[sched.ID] = entryID
		log.Printf("scheduler: loaded schedule %d '%s' (%s)", sched.ID, sched.Name, sched.CronExpr)

		if sched.IntegrityScanEnabled && sched.IntegrityScanCronExpr != "" {
			scanID, err := s.cron.AddFunc(sched.IntegrityScanCronExpr, func() {
				s.runScheduleScan(sched)
			})
			if err != nil {
				log.Printf("scheduler: invalid integrity scan cron expression for schedule %d (%q): %v",
					sched.ID, sched.IntegrityScanCronExpr, err)
				continue
			}
			s.scanIDs[sched.ID] = scanID
			log.Printf("scheduler: loaded integrity scan for schedule %d '%s' (%s)",
				sched.ID, sched.Name, sched.IntegrityScanCronExpr)
		}
	}
	return nil
}

// runSchedule executes a backup for the given schedule using its per-job settings.
func (s *Scheduler) runSchedule(sched db.Schedule) {
	if s.agent.IsRunning() {
		log.Printf("scheduler: skipping scheduled backup '%s': a backup is already in progress", sched.Name)
		return
	}

	log.Printf("scheduler: starting scheduled backup '%s'", sched.Name)

	jobID, err := s.db.CreateJob()
	if err != nil {
		log.Printf("scheduler: create job error: %v", err)
		return
	}

	_ = s.db.UpdateScheduleLastRun(sched.ID)

	if len(sched.SourceDirs) == 0 {
		msg := fmt.Sprintf("schedule '%s' has no source directories configured", sched.Name)
		log.Printf("scheduler: %s", msg)
		_ = s.db.UpdateJob(jobID, "failed", 0, 0, msg)
		return
	}

	retention, _ := sched.DeletedRetentionDuration()
	ctx := context.Background()
	if err := s.agent.Run(ctx, agent.BackupOptions{
		SourceDirs:         sched.SourceDirs,
		ExcludePaths:       sched.ExcludePaths,
		ExcludeRegexes:     sched.ExcludeRegexes,
		CompressionEnabled: sched.CompressionEnabled,
		DeletedRetention:   retention,
		JobID:              jobID,
	}); err != nil {
		if errors.Is(err, agent.ErrAlreadyRunning) {
			log.Printf("scheduler: skipping scheduled backup '%s': %v", sched.Name, err)
			_ = s.db.UpdateJob(jobID, "skipped", 0, 0, err.Error())
			return
		}
		log.Printf("scheduler: backup '%s' failed: %v", sched.Name, err)
		_ = s.db.UpdateJob(jobID, "failed", 0, 0, err.Error())
		notify.SendFailure(s.cfg.NtfyTopic, jobID, err.Error())
	}
}

// runScheduleScan executes an integrity scan scoped to the schedule's source
// directories.
func (s *Scheduler) runScheduleScan(sched db.Schedule) {
	if s.agent.IsScanRunning() {
		log.Printf("scheduler: skipping scan for '%s': already in progress", sched.Name)
		return
	}
	jobID, err := s.db.CreateJobWithType("scan")
	if err != nil {
		log.Printf("scheduler: create scan job: %v", err)
		return
	}
	ctx := context.Background()
	if err := s.agent.RunScan(ctx, jobID, sched.SourceDirs); err != nil {
		if errors.Is(err, agent.ErrScanAlreadyRunning) {
			_ = s.db.UpdateJob(jobID, "skipped", 0, 0, err.Error())
			return
		}
		log.Printf("scheduler: scan for '%s' failed: %v", sched.Name, err)
		_ = s.db.UpdateJob(jobID, "failed", 0, 0, err.Error())
		notify.SendFailure(s.cfg.NtfyTopic, jobID, err.Error())
	}
}
