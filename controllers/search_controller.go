package controllers

import (
	"database/sql"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/example/vulnbank/models"
)

type SearchController struct {
	DB *sql.DB
}

func NewSearchController(db *sql.DB) *SearchController {
	return &SearchController{DB: db}
}

// SearchTransactions — VULN (CWE-89): delegates to models.Search which
// concatenates the raw query term into SQL (see models/transaction.go).
// VULN (CWE-79): also reflects the raw search term back as HTML with no
// encoding, when the client asks for the "html" format — classic reflected
// XSS sink for tools that trace query-param -> HTTP response body.
func (s *SearchController) SearchTransactions(c *gin.Context) {
	term := c.Query("q")
	format := c.Query("format")

	results, err := models.Search(s.DB, term)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "search failed"})
		return
	}

	if format == "html" {
		body := fmt.Sprintf("<h1>Results for: %s</h1><ul>", term) // VULN sink: reflected XSS
		for _, t := range results {
			body += fmt.Sprintf("<li>%s: %.2f</li>", t.Description, t.Amount)
		}
		body += "</ul>"
		c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(body))
		return
	}

	c.JSON(http.StatusOK, results)
}
