package models

import (
	"database/sql"
	"fmt"
)

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"-"`
	Role     string `json:"role"`
	Email    string `json:"email"`
}

// FindByCredentials — VULN (CWE-89): SQL Injection via string concatenation.
// A commercial SAST tool should flag this as a textbook tainted-sink case.
func FindByCredentials(database *sql.DB, username, password string) (*User, error) {
	query := fmt.Sprintf(
		"SELECT id, username, password, role, email FROM users WHERE username = '%s' AND password = '%s'",
		username, password,
	)
	row := database.QueryRow(query) // VULN sink

	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.Email)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// FindByID — secure counterpart, parameterized query, shown for contrast /
// to test that SAST tools don't produce false positives on safe sinks.
func FindByID(database *sql.DB, id string) (*User, error) {
	row := database.QueryRow("SELECT id, username, password, role, email FROM users WHERE id = ?", id)

	var u User
	err := row.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.Email)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func ListAll(database *sql.DB) ([]User, error) {
	rows, err := database.Query("SELECT id, username, password, role, email FROM users")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.Username, &u.Password, &u.Role, &u.Email); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, nil
}

func PromoteToAdmin(database *sql.DB, id string) error {
	// VULN (CWE-89): also injectable — id comes straight from URL param, no validation
	query := fmt.Sprintf("UPDATE users SET role = 'admin' WHERE id = %s", id)
	_, err := database.Exec(query)
	return err
}
