package web

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/seanmatheny/coldcrypt/internal/agent"
	"github.com/seanmatheny/coldcrypt/internal/config"
	"github.com/seanmatheny/coldcrypt/internal/db"
	"github.com/seanmatheny/coldcrypt/internal/scheduler"
)

const sessionCookie = "coldcrypt_session"

// maxBodyBytes limits request bodies to 1 MiB to prevent DoS.
const maxBodyBytes = 1 << 20

type handlers struct {
	cfg      *config.Config
	cfgPath  string
	db       *db.DB
	agent    *agent.Agent
	sched    *scheduler.Scheduler
	sessions *SessionStore
	tlsMode  bool // whether server is running with TLS
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]string{"error": msg})
}

// securityHeaders adds common security headers to every response.
func securityHeaders(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		next(w, r)
	}
}

func (h *handlers) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return securityHeaders(func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie(sessionCookie)
		if err != nil || !h.sessions.ValidateSession(cookie.Value) {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	})
}

// POST /api/auth/login
func (h *handlers) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(h.cfg.WebPasswordHash), []byte(body.Password)); err != nil {
		writeError(w, http.StatusUnauthorized, "invalid password")
		return
	}
	sid := h.sessions.CreateSession()
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    sid,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.tlsMode,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   int(24 * time.Hour / time.Second),
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/auth/logout
func (h *handlers) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	cookie, err := r.Cookie(sessionCookie)
	if err == nil {
		h.sessions.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   h.tlsMode,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
	})
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// POST /api/auth/change-password
func (h *handlers) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Password == "" {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(body.Password), bcrypt.DefaultCost)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "hash error")
		return
	}
	h.cfg.WebPasswordHash = string(hash)
	if err := config.Save(h.cfg, h.cfgPath); err != nil {
		writeError(w, http.StatusInternalServerError, "save config error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GET /api/jobs
func (h *handlers) handleListJobs(w http.ResponseWriter, r *http.Request) {
	jobs, err := h.db.ListJobs(50)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if jobs == nil {
		jobs = []db.Job{}
	}
	writeJSON(w, http.StatusOK, jobs)
}

// GET /api/jobs/:id
func (h *handlers) handleGetJob(w http.ResponseWriter, r *http.Request, id int64) {
	job, err := h.db.GetJob(id)
	if err != nil {
		writeError(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, job)
}

// POST /api/jobs
func (h *handlers) handleCreateJob(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		SourceDirs []string `json:"source_dirs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	dirs := body.SourceDirs
	if len(dirs) == 0 {
		dirs = h.cfg.SourceDirs
	}
	if len(dirs) == 0 {
		writeError(w, http.StatusBadRequest, "no source directories specified")
		return
	}

	jobID, err := h.db.CreateJob()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	go func() {
		if err := h.agent.Run(context.Background(), agent.BackupOptions{
			SourceDirs: dirs,
			JobID:      jobID,
		}); err != nil {
			log.Printf("backup job %d error: %v", jobID, err)
			_ = h.db.UpdateJob(jobID, "failed", 0, 0, err.Error())
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]int64{"job_id": jobID})
}

// GET /api/files
func (h *handlers) handleListFiles(w http.ResponseWriter, r *http.Request) {
	search := r.URL.Query().Get("search")
	files, err := h.db.ListFiles(search)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if files == nil {
		files = []db.FileEntry{}
	}
	writeJSON(w, http.StatusOK, files)
}

// GET /api/files/:id/versions
func (h *handlers) handleGetFileVersions(w http.ResponseWriter, r *http.Request, fileID int64) {
	versions, err := h.db.GetFileVersions(fileID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if versions == nil {
		versions = []db.FileVersion{}
	}
	writeJSON(w, http.StatusOK, versions)
}

// POST /api/files/:id/restore
func (h *handlers) handleRestoreFile(w http.ResponseWriter, r *http.Request, fileID int64) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		VersionNum int    `json:"version_num"`
		OutPath    string `json:"out_path"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.OutPath == "" {
		writeError(w, http.StatusBadRequest, "out_path is required")
		return
	}
	go func() {
		if err := h.agent.RestoreFile(context.Background(), fileID, body.VersionNum, body.OutPath); err != nil {
			log.Printf("restore file %d version %d error: %v", fileID, body.VersionNum, err)
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "restore started", "out_path": body.OutPath})
}

// POST /api/restore
func (h *handlers) handleRestoreByPrefix(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var req struct {
		DisplayPrefix string `json:"display_prefix"`
		OutPath       string `json:"out_path"`
		VersionNum    int    `json:"version_num"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if req.OutPath == "" {
		writeError(w, http.StatusBadRequest, "out_path is required")
		return
	}

	go func() {
		if err := h.agent.RestoreByPrefix(context.Background(), req.DisplayPrefix, req.OutPath, req.VersionNum); err != nil {
			log.Printf("restore prefix %q error: %v", req.DisplayPrefix, err)
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "restore started", "out_path": req.OutPath})
}

// GET /api/schedules
func (h *handlers) handleListSchedules(w http.ResponseWriter, r *http.Request) {
	schedules, err := h.db.ListSchedules()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if schedules == nil {
		schedules = []db.Schedule{}
	}
	writeJSON(w, http.StatusOK, schedules)
}

// POST /api/schedules
func (h *handlers) handleCreateSchedule(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		Name       string   `json:"name"`
		CronExpr   string   `json:"cron_expr"`
		SourceDirs []string `json:"source_dirs"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.Name == "" || body.CronExpr == "" {
		writeError(w, http.StatusBadRequest, "name and cron_expr are required")
		return
	}
	sched, err := h.db.CreateSchedule(body.Name, body.CronExpr, body.SourceDirs)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.sched != nil {
		_ = h.sched.Reload()
	}
	writeJSON(w, http.StatusCreated, sched)
}

// PUT /api/schedules/:id
func (h *handlers) handleUpdateSchedule(w http.ResponseWriter, r *http.Request, id int64) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		Name       string   `json:"name"`
		CronExpr   string   `json:"cron_expr"`
		SourceDirs []string `json:"source_dirs"`
		Enabled    bool     `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if err := h.db.UpdateSchedule(id, body.Name, body.CronExpr, body.SourceDirs, body.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.sched != nil {
		_ = h.sched.Reload()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// DELETE /api/schedules/:id
func (h *handlers) handleDeleteSchedule(w http.ResponseWriter, r *http.Request, id int64) {
	if err := h.db.DeleteSchedule(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if h.sched != nil {
		_ = h.sched.Reload()
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// GET /api/config
func (h *handlers) handleGetConfig(w http.ResponseWriter, r *http.Request) {
	sanitized := map[string]interface{}{
		"remote_host":      h.cfg.RemoteHost,
		"remote_port":      h.cfg.RemotePort,
		"remote_user":      h.cfg.RemoteUser,
		"remote_key_path":  h.cfg.RemoteKeyPath,
		"remote_password":  maskSecret(h.cfg.RemotePassword),
		"remote_base_path": h.cfg.RemoteBasePath,
		"source_dirs":      h.cfg.SourceDirs,
		"web_port":         h.cfg.WebPort,
		"data_dir":         h.cfg.DataDir,
		"web_tls_cert":     h.cfg.WebTLSCert,
		"web_tls_key":      h.cfg.WebTLSKey,
	}
	writeJSON(w, http.StatusOK, sanitized)
}

// PUT /api/config
func (h *handlers) handleUpdateConfig(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
	var body struct {
		RemoteHost     string   `json:"remote_host"`
		RemotePort     int      `json:"remote_port"`
		RemoteUser     string   `json:"remote_user"`
		RemoteKeyPath  string   `json:"remote_key_path"`
		RemotePassword string   `json:"remote_password"`
		RemoteBasePath string   `json:"remote_base_path"`
		SourceDirs     []string `json:"source_dirs"`
		WebPort        int      `json:"web_port"`
		WebTLSCert     string   `json:"web_tls_cert"`
		WebTLSKey      string   `json:"web_tls_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.RemoteHost != "" {
		h.cfg.RemoteHost = body.RemoteHost
	}
	if body.RemotePort != 0 {
		h.cfg.RemotePort = body.RemotePort
	}
	if body.RemoteUser != "" {
		h.cfg.RemoteUser = body.RemoteUser
	}
	if body.RemoteKeyPath != "" {
		h.cfg.RemoteKeyPath = body.RemoteKeyPath
	}
	if body.RemotePassword != "" && body.RemotePassword != "****" {
		h.cfg.RemotePassword = body.RemotePassword
	}
	if body.RemoteBasePath != "" {
		h.cfg.RemoteBasePath = body.RemoteBasePath
	}
	if body.SourceDirs != nil {
		h.cfg.SourceDirs = body.SourceDirs
	}
	if body.WebPort != 0 {
		h.cfg.WebPort = body.WebPort
	}
	if body.WebTLSCert != "" {
		h.cfg.WebTLSCert = body.WebTLSCert
	}
	if body.WebTLSKey != "" {
		h.cfg.WebTLSKey = body.WebTLSKey
	}
	if err := config.Save(h.cfg, h.cfgPath); err != nil {
		writeError(w, http.StatusInternalServerError, fmt.Sprintf("save config: %v", err))
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func maskSecret(s string) string {
	if s == "" {
		return ""
	}
	return "****"
}

// parseIDFromPath extracts an integer ID from a path segment like "/api/files/42/versions".
func parseIDFromPath(path, prefix, suffix string) (int64, bool) {
	// prefix: "/api/files/", suffix: "/versions"
	trimmed := strings.TrimPrefix(path, prefix)
	if suffix != "" {
		trimmed = strings.TrimSuffix(trimmed, suffix)
	}
	id, err := strconv.ParseInt(trimmed, 10, 64)
	return id, err == nil
}

// registerRoutes wires all API handlers onto the provided mux.
func (h *handlers) registerRoutes(mux *http.ServeMux) {
	// Auth
	mux.HandleFunc("/api/auth/login", securityHeaders(h.handleLogin))
	mux.HandleFunc("/api/auth/logout", h.requireAuth(h.handleLogout))
	mux.HandleFunc("/api/auth/change-password", h.requireAuth(h.handleChangePassword))

	// Jobs
	mux.HandleFunc("/api/jobs", h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.handleListJobs(w, r)
		case http.MethodPost:
			h.handleCreateJob(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}))
	mux.HandleFunc("/api/jobs/", h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseIDFromPath(r.URL.Path, "/api/jobs/", "")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid job id")
			return
		}
		h.handleGetJob(w, r, id)
	}))

	// Files
	mux.HandleFunc("/api/files", h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.handleListFiles(w, r)
	}))
	mux.HandleFunc("/api/files/", h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasSuffix(path, "/versions") {
			id, ok := parseIDFromPath(path, "/api/files/", "/versions")
			if !ok {
				writeError(w, http.StatusBadRequest, "invalid file id")
				return
			}
			h.handleGetFileVersions(w, r, id)
		} else if strings.HasSuffix(path, "/restore") {
			id, ok := parseIDFromPath(path, "/api/files/", "/restore")
			if !ok {
				writeError(w, http.StatusBadRequest, "invalid file id")
				return
			}
			h.handleRestoreFile(w, r, id)
		} else {
			writeError(w, http.StatusNotFound, "not found")
		}
	}))

	// Schedules
	mux.HandleFunc("/api/schedules", h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.handleListSchedules(w, r)
		case http.MethodPost:
			h.handleCreateSchedule(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}))
	mux.HandleFunc("/api/schedules/", h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		id, ok := parseIDFromPath(r.URL.Path, "/api/schedules/", "")
		if !ok {
			writeError(w, http.StatusBadRequest, "invalid schedule id")
			return
		}
		switch r.Method {
		case http.MethodPut:
			h.handleUpdateSchedule(w, r, id)
		case http.MethodDelete:
			h.handleDeleteSchedule(w, r, id)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}))

	// Bulk restore
	mux.HandleFunc("/api/restore", h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.handleRestoreByPrefix(w, r)
	}))

	// Config
	mux.HandleFunc("/api/config", h.requireAuth(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			h.handleGetConfig(w, r)
		case http.MethodPut:
			h.handleUpdateConfig(w, r)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	}))
}
