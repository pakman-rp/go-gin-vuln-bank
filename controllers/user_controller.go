package controllers

import (
	"database/sql"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/example/vulnbank/models"
)

type UserController struct {
	DB *sql.DB
}

func NewUserController(db *sql.DB) *UserController {
	return &UserController{DB: db}
}

// GetUser — VULN (CWE-639): IDOR. Any authenticated user can fetch any other
// user's record by guessing the numeric :id, no ownership/role check.
func (u *UserController) GetUser(c *gin.Context) {
	id := c.Param("id")
	user, err := models.FindByID(u.DB, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	c.JSON(http.StatusOK, user)
}

// GetStatement — VULN (CWE-639): same IDOR pattern, exposes another user's
// full transaction history without verifying c.Get("username") owns :id.
func (u *UserController) GetStatement(c *gin.Context) {
	id := c.Param("id")
	txns, err := models.ByUserID(u.DB, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}
	c.JSON(http.StatusOK, txns)
}

// OpenRedirect — VULN (CWE-601): unvalidated redirect target taken directly
// from a query parameter.
func (u *UserController) OpenRedirect(c *gin.Context) {
	target := c.Query("url")
	c.Redirect(http.StatusFound, target) // VULN sink
}
