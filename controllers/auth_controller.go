package controllers

import (
	"crypto/md5"
	"database/sql"
	"encoding/hex"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"

	"github.com/example/vulnbank/models"
)

type AuthController struct {
	DB *sql.DB
}

func NewAuthController(db *sql.DB) *AuthController {
	return &AuthController{DB: db}
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func (a *AuthController) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	// VULN (CWE-532): logging raw password
	log.Printf("[LOGIN] attempt username=%s password=%s", req.Username, req.Password)

	user, err := models.FindByCredentials(a.DB, req.Username, req.Password) // VULN: SQLi sink, see models/user.go
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user.Username,
		"role":     user.Role,
		"exp":      time.Now().Add(24 * time.Hour).Unix(), // VULN: 24h token lifetime, no refresh/rotation
	})
	signed, _ := token.SignedString([]byte("SuperSecretJWT")) // VULN (CWE-798): hardcoded signing key inline

	// VULN (CWE-532): logging issued JWT
	log.Printf("[LOGIN] issued token for %s: %s", user.Username, signed)

	// VULN (CWE-614/CWE-1004): cookie set without Secure/HttpOnly/SameSite
	c.SetCookie("session", signed, 3600*24, "/", "", false, false)

	c.JSON(http.StatusOK, gin.H{"token": signed})
}

type registerRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Email    string `json:"email"`
}

func (a *AuthController) Register(c *gin.Context) {
	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
		return
	}

	// VULN (CWE-521): no password policy enforcement whatsoever (empty/1-char passwords accepted)

	// VULN (CWE-327/CWE-328): MD5 used for "hashing" password, plus predictable
	// salt derived from math/rand (weak PRNG, CWE-338) instead of crypto/rand.
	rand.Seed(time.Now().UnixNano())
	salt := rand.Intn(100000)
	hasher := md5.New()
	hasher.Write([]byte(req.Password))
	hashed := hex.EncodeToString(hasher.Sum(nil))

	_, err := a.DB.Exec(
		"INSERT INTO users (username, password, role, email) VALUES (?, ?, 'user', ?)",
		req.Username, hashed+":"+string(rune(salt)), req.Email,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "could not register"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"status": "registered"})
}
