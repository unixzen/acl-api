package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os/exec"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
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
	return username == "admin" && password == "password"
}

func main() {
	flag.Parse()

	r := chi.NewRouter()

	r.Use(middleware.RequestID)
	r.Use(BasicAuth)
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.URLFormat)
	r.Use(render.SetContentType(render.ContentTypeJSON))

	r.Get("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("root."))
	})

	r.Get("/ping", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("pong"))
	})

	r.Get("/panic", func(w http.ResponseWriter, r *http.Request) {
		panic("test")
	})

	// RESTy routes for "articles" resource
	r.Route("/ips", func(r chi.Router) {
		r.Post("/", AddIPtoFirewall)
	})
	fmt.Println("Server is running on :3333")
	http.ListenAndServe(":3333", r)
}

// CreateArticle persists the posted Article and returns it
// back to the client as an acknowledgement.
func AddIPtoFirewall(w http.ResponseWriter, r *http.Request) {
	var ip Firewall

	err := json.NewDecoder(r.Body).Decode(&ip)

	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	addIPTablesRule := exec.Command("iptables", "-I", "INPUT", "2", "-p", "tcp", "-s", ip.IP, "--dport", "1081", "-j", "ACCEPT")
	output, err := addIPTablesRule.CombinedOutput()
	if err != nil {
		fmt.Printf("Error executing command: %v\n", err)
		if exitError, ok := err.(*exec.ExitError); ok {
			fmt.Printf("Command exited with non-zero status: %d\n", exitError.ExitCode())
		}
		return
	}

	saveIPTablesRule := exec.Command("sh", "-c", "iptables-save > /etc/iptables/rules.v4")
	output1, err := saveIPTablesRule.CombinedOutput()
	if err != nil {
		fmt.Printf("Error executing command: %v\n", err)
		if exitError, ok := err.(*exec.ExitError); ok {
			fmt.Printf("Command exited with non-zero status: %d\n", exitError.ExitCode())
		}
		return
	}

	fmt.Printf("Command output:\n%s\n", output)
	fmt.Printf("Command output:\n%s\n", output1)
	render.Status(r, http.StatusCreated)
}
