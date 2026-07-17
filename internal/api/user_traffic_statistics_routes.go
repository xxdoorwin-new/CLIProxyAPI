package api

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
)

func (s *Server) handleAdminTrafficStatistics(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	report, err := s.trafficStatistics(c, store, "")
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"traffic": report})
}

func (s *Server) handleUserTrafficStatistics(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	principal, ok := s.resolveUserSession(c, store)
	if !ok {
		return
	}
	report, err := s.trafficStatistics(c, store, principal.UserID)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"traffic": report})
}

func (s *Server) trafficStatistics(c *gin.Context, store *usermanagement.SQLiteStore, userID usermanagement.UserID) (*usermanagement.TrafficStatistics, error) {
	return usermanagement.NewTrafficStatisticsService(store, store).Statistics(c.Request.Context(), usermanagement.TrafficStatisticsQuery{
		UserID:      userID,
		From:        strings.TrimSpace(c.Query("from")),
		To:          strings.TrimSpace(c.Query("to")),
		TimeZone:    strings.TrimSpace(c.Query("time_zone")),
		Provider:    strings.TrimSpace(c.Query("provider")),
		Model:       strings.TrimSpace(c.Query("model")),
		Status:      usermanagement.UsageStatus(strings.TrimSpace(c.Query("status"))),
		GroupBy:     usermanagement.TrafficGroupBy(strings.TrimSpace(c.Query("group_by"))),
		Granularity: usermanagement.TrafficGranularity(strings.TrimSpace(c.Query("granularity"))),
	})
}
