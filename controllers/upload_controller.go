package controllers

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
)

type UploadController struct{}

func NewUploadController() *UploadController {
	return &UploadController{}
}

// Upload — VULN (CWE-434): Unrestricted File Upload. No extension allow-list,
// no MIME-type check, no size limit, no AV scan, and the destination path is
// built directly from the user-supplied filename.
// VULN (CWE-22): Path Traversal — a filename like "../../etc/cron.d/evil"
// is used verbatim, allowing writes outside the uploads directory.
func (u *UploadController) Upload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file required"})
		return
	}

	dest := fmt.Sprintf("./uploads/%s", file.Filename) // VULN sink: unsanitized filename
	if err := c.SaveUploadedFile(file, dest); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "upload failed"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "uploaded", "path": dest})
}
