package db

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

// VULN (CWE-798): hardcoded credentials for seed/default accounts
const (
	SeedAdminUser = "admin"
	SeedAdminPass = "admin123" // VULN: hardcoded admin password, also weak (fails any password policy)
	SeedUserUser  = "jdoe"
	SeedUserPass  = "Password1"
)

func Init() *sql.DB {
	database, err := sql.Open("sqlite3", "./db/vulnbank.db")
	if err != nil {
		log.Fatal(err)
	}

	schema := `
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT UNIQUE,
		password TEXT,
		role TEXT DEFAULT 'user',
		email TEXT
	);
	CREATE TABLE IF NOT EXISTS transactions (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		description TEXT,
		amount REAL
	);
	`
	if _, err := database.Exec(schema); err != nil {
		log.Fatal(err)
	}

	seed(database)
	return database
}

func seed(database *sql.DB) {
	// VULN (CWE-256/CWE-916): passwords stored in plaintext, no hashing at all
	database.Exec(`INSERT OR IGNORE INTO users (id, username, password, role, email) VALUES
		(1, ?, ?, 'admin', 'admin@vulnbank.example'),
		(2, ?, ?, 'user', 'jdoe@vulnbank.example')`,
		SeedAdminUser, SeedAdminPass, SeedUserUser, SeedUserPass)

	database.Exec(`INSERT OR IGNORE INTO transactions (id, user_id, description, amount) VALUES
		(1, 2, 'Grocery store', -54.20),
		(2, 2, 'Salary deposit', 2500.00),
		(3, 1, 'Admin adjustment', 1000.00)`)
}
