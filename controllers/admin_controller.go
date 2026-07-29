package controllers

import (
	"database/sql"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/example/vulnbank/models"
)

type AdminController struct {
	DB *sql.DB
}

func NewAdminController(db *sql.DB) *AdminController {
	return &AdminController{DB: db}
}

// ListAllUsers — VULN (CWE-862): Missing Authorization. Route is only
// protected by WeakJWTAuth (proves you *are* someone), never checks
// c.Get("role") == "admin" before returning every user incl. password hashes.
func (a *AdminController) ListAllUsers(c *gin.Context) {
	users, err := models.ListAll(a.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "lookup failed"})
		return
	}
	c.JSON(http.StatusOK, users) // note: also leaks password field via model if json tag changed
}

// PromoteToAdmin — VULN (CWE-269): Privilege Escalation. Any authenticated
// user can promote any account (including their own) to admin; no role
// check, and the id is passed straight into a non-parameterized query
// (models.PromoteToAdmin — also CWE-89).
func (a *AdminController) PromoteToAdmin(c *gin.Context) {
	id := c.Param("id")
	if err := models.PromoteToAdmin(a.DB, id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "promotion failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "promoted", "id": id})
}

// DebugEnv — VULN (CWE-215/CWE-497): exposes full process environment
// (including DB password / JWT secret / cloud keys from .env) over HTTP,
// mimicking an unsecured Spring Actuator /env-style endpoint.
func (a *AdminController) DebugEnv(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"env": os.Environ()})
}
