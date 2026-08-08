package main

import (
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"

	_ "github.com/mattn/go-sqlite3"
)

// VULNERABILITY 1: Hardcoded credentials
// CodeQL: go/hardcoded-credentials
const dbPassword = "supersecret123"
const apiKey = "sk-prod-abc123xyz"

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
	fmt.Fprintf(w, `{"status":"ok","message":"Go DevSecOps demo app"}`)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	fmt.Fprintf(w, `{"status":"healthy"}`)
}

// VULNERABILITY 2: SQL Injection
// CodeQL: go/sql-injection
func getUserHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")
	db, _ := sql.Open("sqlite3", ":memory:")
	// BAD: string concatenation directly into SQL
	query := "SELECT * FROM users WHERE username = '" + username + "'"
	rows, err := db.Query(query)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer rows.Close()
	fmt.Fprintf(w, `{"result":"ok"}`)
}

// VULNERABILITY 3: Command Injection
// CodeQL: go/command-injection
func pingHandler(w http.ResponseWriter, r *http.Request) {
	host := r.URL.Query().Get("host")
	// BAD: user input passed directly to shell
	out, err := exec.Command("sh", "-c", "ping -c 1 "+host).Output()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, `{"output":"%s"}`, string(out))
}

// VULNERABILITY 4: Path Traversal
// CodeQL: go/path-injection
func fileHandler(w http.ResponseWriter, r *http.Request) {
	filename := r.URL.Query().Get("filename")
	// BAD: user controls the file path
	content, err := os.ReadFile(filename)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	fmt.Fprintf(w, `{"content":"%s"}`, string(content))
}

// VULNERABILITY 5: SSRF
// CodeQL: go/ssrf
func fetchHandler(w http.ResponseWriter, r *http.Request) {
	url := r.URL.Query().Get("url")
	// BAD: user-controlled URL fetched directly
	resp, err := http.Get(url)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	fmt.Fprintf(w, `{"content":"%s"}`, string(body))
}
