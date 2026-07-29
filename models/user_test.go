package models

import (
	"database/sql"
	"testing"

	_ "github.com/mattn/go-sqlite3"
)

func setupTestDB(t *testing.T) *sql.DB {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`CREATE TABLE users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		password TEXT,
		role TEXT DEFAULT 'user',
		email TEXT
	)`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO users (username, password, role, email) VALUES ('tester', 'pw', 'user', 't@example.com')`)
	if err != nil {
		t.Fatal(err)
	}
	return db
}

func TestFindByID(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	u, err := FindByID(db, "1")
	if err != nil {
		t.Fatalf("expected user, got error: %v", err)
	}
	if u.Username != "tester" {
		t.Errorf("expected username 'tester', got %q", u.Username)
	}
}

// TestFindByCredentials_SQLiRegression documents the injection surface so
// SAST/DAST results can be cross-checked against a functional test: this
// test intentionally demonstrates a boolean-based bypass via the vulnerable
// concatenated query.
func TestFindByCredentials_SQLiRegression(t *testing.T) {
	db := setupTestDB(t)
	defer db.Close()

	_, err := FindByCredentials(db, "tester' -- ", "irrelevant")
	if err != nil {
		t.Fatalf("SQL injection bypass expected to succeed against vulnerable query, got error: %v", err)
	}
}
