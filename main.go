package main

import (
	"encoding/json"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/httprate"
	"github.com/go-chi/render"
)

type Firewall struct {
	IP string `json:"ip"`
}

func BasicAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		user, pass, ok := r.BasicAuth()
		if !ok || !checkCredentials(user, pass) {
			w.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func checkCredentials(username, password string) bool {
	return username == os.Getenv("USERNAME") && password == os.Getenv("PASSWORD")
}

func LoggerMiddleware(logger *slog.Logger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ww := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			t1 := time.Now()
			defer func() {
				logger.Info("request completed",
					slog.String("method", r.Method),
					slog.String("path", r.URL.Path),
					slog.Int("status", ww.Status()),
					slog.Int("size", ww.BytesWritten()),
					slog.Duration("duration", time.Since(t1)),
				)
			}()

			next.ServeHTTP(ww, r)
		})
	}
}

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	flag.Parse()

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(BasicAuth)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(httprate.LimitByIP(100, time.Minute))
	r.Use(render.SetContentType(render.ContentTypeJSON))
	r.Use(LoggerMiddleware(logger))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("root."))
	})

	r.Route("/ips", func(r chi.Router) {
		r.Post("/", AddIPtoFirewall)
	})
	logger.Info("Server is running on :3333")
	http.ListenAndServe(":3333", r)
}

func AddIPtoFirewall(w http.ResponseWriter, r *http.Request) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	var ip Firewall

	err := json.NewDecoder(r.Body).Decode(&ip)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addIPTablesRule := exec.Command("iptables", "-I", "INPUT", "2", "-p", "tcp", "-s", ip.IP, "--dport", "1081", "-j", "ACCEPT")
	_, err = addIPTablesRule.CombinedOutput()
	if err != nil {
		logger.Error("Error executing command: %v\n", err)
		//fmt.Printf("Error executing command: %v\n", err)
		if exitError, ok := err.(*exec.ExitError); ok {
			//fmt.Printf("Command exited with non-zero status: %d\n", exitError.ExitCode())
			logger.Error("Command exited with non-zero status: %d\n", exitError.ExitCode())
		}
		return
	}
	logger.Info("iptables added", ip.IP, "at chain rules")

	saveIPTablesRule := exec.Command("sh", "-c", "iptables-save > /etc/iptables/rules.v4")
	_, err = saveIPTablesRule.CombinedOutput()
	if err != nil {
		logger.Error("Error executing command: %v\n", err)
		if exitError, ok := err.(*exec.ExitError); ok {
			logger.Error("Command exited with non-zero status: %d\n", exitError.ExitCode())
		}
		return
	}

	logger.Info("iptables saved rules")
	render.Status(r, http.StatusCreated)
}
