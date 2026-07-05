package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/buildinfo"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
)

func (s *Server) managementAccessMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-CPA-VERSION", buildinfo.Version)
		c.Header("X-CPA-COMMIT", buildinfo.Commit)
		c.Header("X-CPA-BUILD-DATE", buildinfo.BuildDate)

		if s.tryManagementUserSession(c) {
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

func (s *Server) tryManagementUserSession(c *gin.Context) bool {
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
	c.Set("userPrincipal", principal)
	if principal.Role == usermanagement.UserRoleAdmin {
		c.Set("managementAuth", "user_session")
		return true
	}
	if s.cfg.UserManagement.Quota.AllowUserViewTotalRemaining && isOrdinaryUserManagementRoute(c) {
		c.Set("managementAuth", "ordinary_user_session")
		return true
	}
	if principal.Role != usermanagement.UserRoleAdmin {
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin role required"})
		return false
	}
	return true
}

func isOrdinaryUserManagementRoute(c *gin.Context) bool {
	if c == nil || c.Request == nil || c.Request.URL == nil {
		return false
	}
	path := strings.TrimRight(c.Request.URL.Path, "/")
	switch {
	case c.Request.Method == http.MethodGet && path == "/v0/management/auth-files":
		return true
	case c.Request.Method == http.MethodPost && path == "/v0/management/api-call":
		return true
	default:
		return false
	}
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
