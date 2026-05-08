package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"runtime"
	"time"

	"github.com/gorilla/mux"
	"github.com/itsgeorgema/neural-ebpf/daemon/internal/monitor"
)

type Server struct {
	mon    *monitor.Monitor
	router *mux.Router
	port   string
}

func New(mon *monitor.Monitor, port string) *Server {
	s := &Server{mon: mon, port: port, router: mux.NewRouter()}
	s.routes()
	return s
}

func (s *Server) Run() error {
	srv := &http.Server{
		Addr:         ":" + s.port,
		Handler:      s.router,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 0, // SSE streams need no write timeout
	}
	return srv.ListenAndServe()
}

func (s *Server) routes() {
	s.router.Use(corsMiddleware)
	s.router.HandleFunc("/health", s.handleHealth).Methods("GET")
	s.router.HandleFunc("/events", s.handleEvents).Methods("GET")
	s.router.HandleFunc("/mitigate", s.handleMitigate).Methods("POST")
	s.router.HandleFunc("/processes", s.handleProcesses).Methods("GET")
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status":    "ok",
		"time":      time.Now().Format(time.RFC3339),
		"cpu_cores": runtime.NumCPU(),
	})
}

func (s *Server) handleProcesses(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.mon.GetProcesses())
}

func (s *Server) handleMitigate(w http.ResponseWriter, r *http.Request) {
	var req monitor.MitigationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	result := s.mon.Mitigate(req)
	status := http.StatusOK
	if !result.Success {
		status = http.StatusInternalServerError
	}
	writeJSON(w, status, result)
}

// handleEvents streams kernel events as Server-Sent Events (SSE).
func (s *Server) handleEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	ch := s.mon.Subscribe()
	defer s.mon.Unsubscribe(ch)

	log.Printf("[sse] client connected: %s", r.RemoteAddr)

	// Send a heartbeat every 15s to keep the connection alive
	heartbeat := time.NewTicker(15 * time.Second)
	defer heartbeat.Stop()

	for {
		select {
		case ev, ok := <-ch:
			if !ok {
				return
			}
			data, err := json.Marshal(ev)
			if err != nil {
				continue
			}
			fmt.Fprintf(w, "event: kernel_event\ndata: %s\n\n", data)
			flusher.Flush()

		case <-heartbeat.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()

		case <-r.Context().Done():
			log.Printf("[sse] client disconnected: %s", r.RemoteAddr)
			return
		}
	}
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
