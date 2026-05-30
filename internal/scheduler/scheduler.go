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
	scanID   cronv3.EntryID
}

// New creates a new Scheduler.
func New(database *db.DB, a *agent.Agent, cfg *config.Config) *Scheduler {
	return &Scheduler{
		cfg:      cfg,
		db:       database,
		agent:    a,
		entryIDs: make(map[int64]cronv3.EntryID),
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
	s.scanID = 0

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
		entryID, err := s.cron.AddFunc(sched.CronExpr, func() {
			s.runSchedule(sched.ID, sched.Name, sched.SourceDirs)
		})
		if err != nil {
			log.Printf("scheduler: invalid cron expr for schedule %d (%s): %v", sched.ID, sched.CronExpr, err)
			continue
		}
		s.entryIDs[sched.ID] = entryID
		log.Printf("scheduler: loaded schedule %d '%s' (%s)", sched.ID, sched.Name, sched.CronExpr)
	}
	s.loadScanSchedule()
	return nil
}

func (s *Scheduler) loadScanSchedule() {
	if !s.cfg.IntegrityScanEnabled || s.cfg.IntegrityScanCronExpr == "" {
		return
	}
	entryID, err := s.cron.AddFunc(s.cfg.IntegrityScanCronExpr, func() {
		s.runScan()
	})
	if err != nil {
		log.Printf("scheduler: invalid integrity scan cron expression %q: %v", s.cfg.IntegrityScanCronExpr, err)
		return
	}
	s.scanID = entryID
	log.Printf("scheduler: loaded integrity scan schedule (%s)", s.cfg.IntegrityScanCronExpr)
}

// runSchedule executes a backup for the given schedule.
func (s *Scheduler) runSchedule(scheduleID int64, name string, sourceDirs []string) {
	if s.agent.IsRunning() {
		log.Printf("scheduler: skipping scheduled backup '%s': a backup is already in progress", name)
		return
	}

	log.Printf("scheduler: starting scheduled backup '%s'", name)

	jobID, err := s.db.CreateJob()
	if err != nil {
		log.Printf("scheduler: create job error: %v", err)
		return
	}

	_ = s.db.UpdateScheduleLastRun(scheduleID)

	dirs := sourceDirs
	if len(dirs) == 0 {
		dirs = s.cfg.SourceDirs
	}

	ctx := context.Background()
	if err := s.agent.Run(ctx, agent.BackupOptions{
		SourceDirs:     dirs,
		ExcludePaths:   s.cfg.ExcludePaths,
		ExcludeRegexes: s.cfg.ExcludeRegexes,
		JobID:          jobID,
	}); err != nil {
		if errors.Is(err, agent.ErrAlreadyRunning) {
			log.Printf("scheduler: skipping scheduled backup '%s': %v", name, err)
			_ = s.db.UpdateJob(jobID, "skipped", 0, 0, err.Error())
			return
		}
		log.Printf("scheduler: backup '%s' failed: %v", name, err)
		_ = s.db.UpdateJob(jobID, "failed", 0, 0, err.Error())
		notify.SendFailure(s.cfg.NtfyTopic, jobID, err.Error())
	}
}

func (s *Scheduler) runScan() {
	if s.agent.IsScanRunning() {
		log.Printf("scheduler: skipping scan: already in progress")
		return
	}
	jobID, err := s.db.CreateJobWithType("scan")
	if err != nil {
		log.Printf("scheduler: create scan job: %v", err)
		return
	}
	ctx := context.Background()
	if err := s.agent.RunScan(ctx, jobID); err != nil {
		if errors.Is(err, agent.ErrScanAlreadyRunning) {
			_ = s.db.UpdateJob(jobID, "skipped", 0, 0, err.Error())
			return
		}
		log.Printf("scheduler: scan failed: %v", err)
		_ = s.db.UpdateJob(jobID, "failed", 0, 0, err.Error())
		notify.SendFailure(s.cfg.NtfyTopic, jobID, err.Error())
	}
}
