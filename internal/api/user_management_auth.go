package api

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/buildinfo"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
)

func (s *Server) managementAccessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-CPA-VERSION", buildinfo.Version)
		c.Header("X-CPA-COMMIT", buildinfo.Commit)
		c.Header("X-CPA-BUILD-DATE", buildinfo.BuildDate)

		if s.tryAdminSession(c) {
			c.Set("managementAuth", "user_session")
			c.Next()
			return
		}
		if c.IsAborted() {
			return
		}

		clientIP := c.ClientIP()
		localClient := clientIP == "127.0.0.1" || clientIP == "::1"
		provided := managementKeyFromRequest(c)
		allowed, statusCode, errMsg := s.mgmt.AuthenticateManagementKey(clientIP, localClient, provided)
		if !allowed {
			c.AbortWithStatusJSON(statusCode, gin.H{"error": errMsg})
			return
		}
		c.Set("managementAuth", "management_key")
		c.Next()
	}
}

func (s *Server) tryAdminSession(c *gin.Context) bool {
	if s == nil || s.cfg == nil || !s.cfg.UserManagement.Enabled {
		return false
	}
	token := userSessionTokenFromRequest(c)
	if token == "" {
		return false
	}
	s.userManagementMu.RLock()
	store := s.userStore
	s.userManagementMu.RUnlock()
	if store == nil {
		return false
	}
	principal, err := usermanagement.NewSessionService(store, store).ResolvePrincipal(c.Request.Context(), token)
	if err != nil {
		return false
	}
	if principal.Role != usermanagement.UserRoleAdmin {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin role required"})
		return false
	}
	c.Set("userPrincipal", principal)
	return true
}

func managementKeyFromRequest(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if key := userSessionTokenFromRequest(c); key != "" {
		return key
	}
	return c.GetHeader("X-Management-Key")
}
