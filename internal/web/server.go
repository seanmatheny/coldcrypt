package web

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"github.com/seanmatheny/coldcrypt/internal/agent"
	"github.com/seanmatheny/coldcrypt/internal/config"
	"github.com/seanmatheny/coldcrypt/internal/db"
	"github.com/seanmatheny/coldcrypt/internal/scheduler"
)

//go:embed static
var staticFS embed.FS

// Server is the Coldcrypt web server.
type Server struct {
	cfg            *config.Config
	cfgPath        string
	secretsCfgPath string
	db             *db.DB
	agent          *agent.Agent
	sched          *scheduler.Scheduler
	version        string
}

// New creates a new web Server.
func New(cfg *config.Config, cfgPath string, secretsCfgPath string, database *db.DB, a *agent.Agent, sched *scheduler.Scheduler, version string) *Server {
	return &Server{
		cfg:            cfg,
		cfgPath:        cfgPath,
		secretsCfgPath: secretsCfgPath,
		db:             database,
		agent:          a,
		sched:          sched,
		version:        version,
	}
}

// Start starts the HTTP(S) server.
func (s *Server) Start() error {
	mux := http.NewServeMux()

	h := &handlers{
		cfg:            s.cfg,
		cfgPath:        s.cfgPath,
		secretsCfgPath: s.secretsCfgPath,
		db:             s.db,
		agent:          s.agent,
		sched:          s.sched,
		sessions:       NewSessionStore(),
		tlsMode:        s.cfg.WebTLSCert != "" && s.cfg.WebTLSKey != "",
		version:        s.version,
	}
	h.registerRoutes(mux)

	// Serve static files under /static/
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		return fmt.Errorf("static fs: %w", err)
	}
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticSub))))

	// Safari prefers /favicon.ico at the site root over <link> icons.
	mux.HandleFunc("/favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		data, err := staticFS.ReadFile("static/img/favicon.ico")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "image/x-icon")
		_, _ = w.Write(data)
	})

	// Serve index.html for root and any unmatched paths.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		data, err := staticFS.ReadFile("static/index.html")
		if err != nil {
			http.Error(w, "index.html not found", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write(data)
	})

	addr := fmt.Sprintf(":%d", s.cfg.WebPort)
	log.Printf("web: listening on %s", addr)

	if s.cfg.WebTLSCert != "" && s.cfg.WebTLSKey != "" {
		log.Printf("web: TLS enabled")
		return http.ListenAndServeTLS(addr, s.cfg.WebTLSCert, s.cfg.WebTLSKey, mux)
	}
	return http.ListenAndServe(addr, mux)
}
