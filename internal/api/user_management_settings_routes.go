package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

type userManagementSettingsResponse struct {
	Enabled bool `json:"enabled"`
}

func (s *Server) handleAdminGetUserManagementSettings(c *gin.Context) {
	enabled := false
	if s != nil && s.cfg != nil {
		enabled = s.cfg.UserManagement.Enabled
	}
	c.JSON(http.StatusOK, userManagementSettingsResponse{Enabled: enabled})
}

func (s *Server) handleAdminPatchUserManagementSettings(c *gin.Context) {
	var body struct {
		Enabled *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.Enabled == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if s == nil || s.configFilePath == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config file path is not available"})
		return
	}

	enabled := *body.Enabled
	if err := config.SaveConfigPreserveCommentsUpdateNestedBool(s.configFilePath, []string{"user-management", "enabled"}, enabled); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": err.Error()})
		return
	}
	newCfg, err := config.LoadConfig(s.configFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reload_failed", "message": err.Error()})
		return
	}
	s.UpdateClients(newCfg)

	c.JSON(http.StatusOK, userManagementSettingsResponse{Enabled: newCfg.UserManagement.Enabled})
}
