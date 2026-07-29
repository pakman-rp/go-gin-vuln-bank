package models

import (
	"database/sql"
	"fmt"
)

type Transaction struct {
	ID          int     `json:"id"`
	UserID      int     `json:"user_id"`
	Description string  `json:"description"`
	Amount      float64 `json:"amount"`
}

// Search — VULN (CWE-89): SQL Injection, search term concatenated directly
// into a LIKE clause. Classic reflected search-box injection pattern.
func Search(database *sql.DB, term string) ([]Transaction, error) {
	query := fmt.Sprintf("SELECT id, user_id, description, amount FROM transactions WHERE description LIKE '%%%s%%'", term)
	rows, err := database.Query(query) // VULN sink
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Transaction
	for rows.Next() {
		var t Transaction
		if err := rows.Scan(&t.ID, &t.UserID, &t.Description, &t.Amount); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}

func ByUserID(database *sql.DB, userID string) ([]Transaction, error) {
	// secure counterpart
	rows, err := database.Query("SELECT id, user_id, description, amount FROM transactions WHERE user_id = ?", userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Transaction
	for rows.Next() {
		var t Transaction
		if err := rows.Scan(&t.ID, &t.UserID, &t.Description, &t.Amount); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}
