// Package gui serves a local web UI. It listens on loopback only, requires a random
// token, validates the Host header, and never accepts file paths from the browser:
// the client can only refer to findings by the ids of the last scan.
package gui

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"runtime"
	"sync"
	"time"

	"devsweep/internal/clean"
	"devsweep/internal/rules"
	"devsweep/internal/scan"
)

//go:embed web/index.html
var indexHTML []byte

type server struct {
	rs        []rules.Rule
	opts      scan.Options
	token     string
	host      string
	protected bool // browser mode: enforce Host + token. Desktop mode has no listener, so no checks.

	op       sync.Mutex // one scan/clean at a time
	mu       sync.Mutex // guards findings
	findings []scan.Finding
}

type item struct {
	ID int `json:"id"`
	scan.Finding
	Command bool `json:"command"` // an official clean command will be used
}

type cleanReq struct {
	IDs  []int  `json:"ids"`
	Mode string `json:"mode"`
}

type cleanRes struct {
	ID      int    `json:"id"`
	Name    string `json:"name"`
	Path    string `json:"path"`
	Size    int64  `json:"size"`
	Method  string `json:"method"`
	Skipped int    `json:"skipped"`
	Error   string `json:"error,omitempty"`
}

// Run starts the server and blocks. port 0 picks a free port.
func Run(rs []rules.Rule, opts scan.Options, port int, open bool) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	var tok [16]byte
	if _, err := rand.Read(tok[:]); err != nil {
		return err
	}
	s := &server{rs: rs, opts: opts, token: hex.EncodeToString(tok[:]), host: ln.Addr().String(), protected: true}
	mux := s.routes()

	url := fmt.Sprintf("http://%s/?t=%s", s.host, s.token)
	fmt.Println("devsweep GUI:", url)
	fmt.Println("Press Ctrl+C to stop.")
	if open {
		go openBrowser(url)
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 10 * time.Second}
	return srv.Serve(ln)
}

// Handler returns the UI + API for an embedded desktop window (Wails asset handler).
// There is no network listener in this mode, so only the window itself can reach it.
func Handler(rs []rules.Rule, opts scan.Options) http.Handler {
	s := &server{rs: rs, opts: opts}
	return s.routes()
}

func (s *server) routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.index)
	mux.HandleFunc("/api/scan", s.guard(s.scan))
	mux.HandleFunc("/api/clean", s.guard(s.clean))
	mux.HandleFunc("/api/quarantine", s.guard(s.quarantine))
	mux.HandleFunc("/api/restore", s.guard(s.restore))
	mux.HandleFunc("/api/purge", s.guard(s.purge))
	return mux
}

func openBrowser(url string) {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	case "darwin":
		cmd = exec.Command("open", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	_ = cmd.Start()
}

func (s *server) hostOK(r *http.Request) bool { return !s.protected || r.Host == s.host }

func (s *server) index(w http.ResponseWriter, r *http.Request) {
	if !s.hostOK(r) || r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write(indexHTML)
}

// guard checks the Host header (DNS rebinding) and the token header (CSRF); a custom
// header also forces a CORS preflight that this server never approves.
func (s *server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Devsweep-Token")
		if !s.hostOK(r) || (s.protected && subtle.ConstantTimeCompare([]byte(got), []byte(s.token)) != 1) {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		h(w, r)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func (s *server) scan(w http.ResponseWriter, r *http.Request) {
	if !s.op.TryLock() {
		fail(w, http.StatusConflict, "another operation is running")
		return
	}
	defer s.op.Unlock()
	found := scan.Run(r.Context(), s.rs, s.opts)
	s.mu.Lock()
	s.findings = found
	s.mu.Unlock()
	items := make([]item, len(found))
	for i, f := range found {
		_, err := exec.LookPath(firstOr(f.Clean))
		items[i] = item{ID: i, Finding: f, Command: len(f.Clean) > 0 && err == nil}
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "roots": s.opts.Roots})
}

func firstOr(c []string) string {
	if len(c) == 0 {
		return ""
	}
	return c[0]
}

func (s *server) clean(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req cleanReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	mode := clean.Mode(req.Mode)
	if mode != clean.Quarantine && mode != clean.Delete {
		fail(w, http.StatusBadRequest, "mode must be quarantine or delete")
		return
	}
	if !s.op.TryLock() {
		fail(w, http.StatusConflict, "another operation is running")
		return
	}
	defer s.op.Unlock()

	s.mu.Lock()
	snapshot := append([]scan.Finding(nil), s.findings...)
	s.mu.Unlock()

	seen := map[int]bool{}
	var picked []int
	for _, id := range req.IDs {
		if id < 0 || id >= len(snapshot) || seen[id] {
			continue
		}
		seen[id] = true
		picked = append(picked, id)
	}
	if len(picked) == 0 {
		fail(w, http.StatusBadRequest, "nothing selected (scan again?)")
		return
	}
	c, err := clean.New(mode)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	// Not tied to the request: a closed tab must not leave a half-finished clean.
	ctx := context.Background()
	out := make([]cleanRes, 0, len(picked))
	for _, id := range picked {
		f := snapshot[id]
		res := c.Apply(ctx, f)
		cr := cleanRes{ID: id, Name: f.Name, Path: f.Path, Size: f.Size, Method: res.Method, Skipped: res.Skipped}
		if res.Err != nil {
			cr.Error = res.Err.Error()
		}
		out = append(out, cr)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": out})
}

func (s *server) quarantine(w http.ResponseWriter, r *http.Request) {
	batches, err := clean.Batches()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	var size int64
	if root, err := clean.Root(); err == nil {
		size, _ = scan.DirSize(r.Context(), root)
	}
	if batches == nil {
		batches = []string{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"batches": batches, "size": size})
}

func (s *server) restore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	var req struct {
		Batch string `json:"batch"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		fail(w, http.StatusBadRequest, "bad request")
		return
	}
	batches, err := clean.Batches()
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	known := false
	for _, b := range batches {
		known = known || b == req.Batch
	}
	if !known {
		fail(w, http.StatusBadRequest, "unknown batch")
		return
	}
	n, skipped, err := clean.Restore(req.Batch)
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int{"restored": n, "skipped": skipped})
}

func (s *server) purge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		fail(w, http.StatusMethodNotAllowed, "POST only")
		return
	}
	freed, err := clean.Purge(r.Context())
	if err != nil {
		fail(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]int64{"freed": freed})
}
