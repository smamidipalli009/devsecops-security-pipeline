package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	_ "github.com/mattn/go-sqlite3"
)

// FIX 1: Credentials from environment variables
var dbPassword = os.Getenv("DB_PASSWORD")
var apiKey = os.Getenv("API_KEY")

var safeDir = "/app/safe_files"
var allowedHosts = map[string]bool{
	"api.example.com":  true,
	"data.example.com": true,
}

func main() {
	http.HandleFunc("/", indexHandler)
	http.HandleFunc("/health", healthHandler)
	http.HandleFunc("/user", getUserHandler)
	http.HandleFunc("/ping", pingHandler)
	http.HandleFunc("/file", fileHandler)
	http.HandleFunc("/fetch", fetchHandler)
	fmt.Println("Server running on :9001")
	http.ListenAndServe(":9001", nil)
}

func indexHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"ok","message":"Go DevSecOps demo app (hardened)"}`)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"healthy"}`)
}

// FIX 2: Parameterised query
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	db, _ := sql.Open("sqlite3", ":memory:")
	rows, err := db.Query("SELECT * FROM users WHERE username = ?", username)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, `{"result":"ok"}`)
}

// FIX 3: exec.Command with list args — no shell interpolation
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	out, err := exec.Command("ping", "-c", "1", host).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, `{"output":"%s"}`, string(out))
}

// FIX 4: Path sanitisation + safe directory check
func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	safePath := filepath.Join(safeDir, filepath.Base(filename))
	if !strings.HasPrefix(safePath, safeDir) {
		http.Error(w, "access denied", 403)
		return
	}
	content, err := os.ReadFile(safePath)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, `{"content":"%s"}`, string(content))
}

// FIX 5: Host allowlist — SSRF prevented
func fetchHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	parsed, err := http.NewRequest("GET", url, nil)
	if err != nil || !allowedHosts[parsed.URL.Hostname()] {
		http.Error(w, "host not permitted", 403)
		return
	}
	resp, err := http.DefaultClient.Do(parsed)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(w, `{"content":"%s"}`, string(body))
}
