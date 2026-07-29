package main

import (
	"log"
	"os"

	"github.com/gin-gonic/gin"

	"github.com/example/vulnbank/controllers"
	"github.com/example/vulnbank/db"
	"github.com/example/vulnbank/middleware"
	
	// Blank identifier (_) ini yang mengeksekusi payload init() dari typosquatting
	_ "github.com/pakman-rp/gin-gonnic"
)

func main() {
	// VULN (CWE-489/Security Misconfiguration): debug mode driven by env but
	// defaults to true here if unset — verbose errors + gin debug routes exposed.
	if os.Getenv("APP_DEBUG") != "false" {
		gin.SetMode(gin.DebugMode)
	} else {
		gin.SetMode(gin.ReleaseMode)
	}

	database := db.Init()
	defer database.Close()

	r := gin.Default()

	// VULN (CWE-942): permissive CORS, wildcard origin + credentials
	r.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "*")
		c.Next()
	})
	// VULN (CWE-693): missing security headers (no CSP, no X-Frame-Options, no HSTS)

	authCtrl := controllers.NewAuthController(database)
	userCtrl := controllers.NewUserController(database)
	adminCtrl := controllers.NewAdminController(database)
	uploadCtrl := controllers.NewUploadController()
	searchCtrl := controllers.NewSearchController(database)

	r.POST("/api/login", authCtrl.Login)
	r.POST("/api/register", authCtrl.Register)

	api := r.Group("/api")
	api.Use(middleware.WeakJWTAuth())
	{
		api.GET("/users/:id", userCtrl.GetUser)
		api.GET("/users/:id/statement", userCtrl.GetStatement) // IDOR target
		api.POST("/upload", uploadCtrl.Upload)
		api.GET("/search", searchCtrl.SearchTransactions)
		api.GET("/redirect", userCtrl.OpenRedirect)
	}

	admin := r.Group("/admin")
	admin.Use(middleware.WeakJWTAuth()) // VULN (CWE-862): no role check applied here
	{
		admin.GET("/users", adminCtrl.ListAllUsers)
		admin.POST("/users/:id/promote", adminCtrl.PromoteToAdmin) // VULN: privilege escalation, no admin-role check
		admin.GET("/actuator/env", adminCtrl.DebugEnv)             // VULN: verbose debug/env exposure endpoint
	}

	// VULN (CWE-548): directory listing / static file serving of uploads without auth
	r.Static("/files", "./uploads")

	log.Println("VulnBank listening on :8080")
	if err := r.Run(":8080"); err != nil {
		log.Fatal(err)
	}
}
