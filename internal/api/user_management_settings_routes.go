package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
)

type userManagementSettingsResponse struct {
	Enabled                     bool `json:"enabled"`
	AllowUserViewTotalRemaining bool `json:"allow_user_view_total_remaining"`
}

func (s *Server) handleAdminGetUserManagementSettings(c *gin.Context) {
	enabled := false
	allowUserViewTotalRemaining := false
	if s != nil && s.cfg != nil {
		enabled = s.cfg.UserManagement.Enabled
		allowUserViewTotalRemaining = s.cfg.UserManagement.Quota.AllowUserViewTotalRemaining
	}
	c.JSON(http.StatusOK, userManagementSettingsResponse{
		Enabled:                     enabled,
		AllowUserViewTotalRemaining: allowUserViewTotalRemaining,
	})
}

func (s *Server) handleAdminPatchUserManagementSettings(c *gin.Context) {
	var body struct {
		Enabled                     *bool `json:"enabled"`
		AllowUserViewTotalRemaining *bool `json:"allow_user_view_total_remaining"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || (body.Enabled == nil && body.AllowUserViewTotalRemaining == nil) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	if s == nil || s.configFilePath == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "config file path is not available"})
		return
	}

	if body.Enabled != nil {
		if err := config.SaveConfigPreserveCommentsUpdateNestedBool(s.configFilePath, []string{"user-management", "enabled"}, *body.Enabled); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": err.Error()})
			return
		}
	}
	if body.AllowUserViewTotalRemaining != nil {
		if err := config.SaveConfigPreserveCommentsUpdateNestedBool(s.configFilePath, []string{"user-management", "quota", "allow-user-view-total-remaining"}, *body.AllowUserViewTotalRemaining); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "write_failed", "message": err.Error()})
			return
		}
	}
	newCfg, err := config.LoadConfig(s.configFilePath)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "reload_failed", "message": err.Error()})
		return
	}
	s.UpdateClients(newCfg)

	c.JSON(http.StatusOK, userManagementSettingsResponse{
		Enabled:                     newCfg.UserManagement.Enabled,
		AllowUserViewTotalRemaining: newCfg.UserManagement.Quota.AllowUserViewTotalRemaining,
	})
}
