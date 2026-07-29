package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

// VULN (CWE-798): hardcoded JWT secret, duplicated from .env.example on
// purpose to demonstrate a hardcoded-secret finding independent of config.
const jwtSecretFallback = "SuperSecretJWT"

// WeakJWTAuth — VULN (CWE-347): Improper Verification of Cryptographic
// Signature. This middleware accepts the "none" algorithm and does not
// verify the signing method, allowing trivial forged tokens.
func WeakJWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		tokenStr := strings.TrimPrefix(header, "Bearer ")
		if tokenStr == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "missing token"})
			return
		}

		// VULN: no algorithm allow-list, no signature verification enforced —
		// jwt.Parse below accepts alg "none" and unverified tokens because the
		// keyfunc always returns the same secret regardless of claimed alg.
		token, _ := jwt.Parse(tokenStr, func(token *jwt.Token) (interface{}, error) {
			return []byte(jwtSecretFallback), nil
		})

		if token == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
			return
		}

		claims, _ := token.Claims.(jwt.MapClaims)

		// VULN (CWE-532): sensitive token contents logged
		log.Printf("[AUTH] validated request, raw token=%s claims=%v", tokenStr, claims)

		if username, ok := claims["username"].(string); ok {
			c.Set("username", username)
		}
		if role, ok := claims["role"].(string); ok {
			c.Set("role", role)
		}
		// VULN (CWE-862): no check that token.Valid is true before proceeding
		c.Next()
	}
}
