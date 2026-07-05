package api

import (
	"net/http"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
)

func (s *Server) handleAdminListUsers(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	users, err := store.ListUsers(c.Request.Context(), usermanagement.UserFilter{
		Status: usermanagement.UserStatus(strings.TrimSpace(c.Query("status"))),
		Role:   usermanagement.UserRole(strings.TrimSpace(c.Query("role"))),
		Query:  c.Query("query"),
		Limit:  intQuery(c, "limit"),
		Offset: intQuery(c, "offset"),
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": toUserResponses(users)})
}

func (s *Server) handleAdminListPendingUsers(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	users, err := store.ListUsers(c.Request.Context(), usermanagement.UserFilter{
		Status: usermanagement.UserStatusPending,
		Limit:  intQuery(c, "limit"),
		Offset: intQuery(c, "offset"),
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"users": toUserResponses(users)})
}

func (s *Server) handleAdminGetUser(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	user, err := store.GetUser(c.Request.Context(), usermanagement.UserID(c.Param("id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": toUserResponse(user)})
}

func (s *Server) handleAdminApproveUser(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	var body struct {
		Role string `json:"role"`
	}
	_ = c.ShouldBindJSON(&body)
	user, err := usermanagement.NewUserLifecycleService(store, store).ApproveUser(
		c.Request.Context(),
		usermanagement.UserID(c.Param("id")),
		usermanagement.UserRole(strings.TrimSpace(body.Role)),
	)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": toUserResponse(user)})
}

func (s *Server) handleAdminRejectUser(c *gin.Context) {
	s.handleAdminUserStatusAction(c, func(service *usermanagement.UserLifecycleService, userID usermanagement.UserID) (*usermanagement.User, error) {
		return service.RejectUser(c.Request.Context(), userID)
	})
}

func (s *Server) handleAdminSuspendUser(c *gin.Context) {
	s.handleAdminUserStatusAction(c, func(service *usermanagement.UserLifecycleService, userID usermanagement.UserID) (*usermanagement.User, error) {
		return service.SuspendUser(c.Request.Context(), userID)
	})
}

func (s *Server) handleAdminReactivateUser(c *gin.Context) {
	s.handleAdminUserStatusAction(c, func(service *usermanagement.UserLifecycleService, userID usermanagement.UserID) (*usermanagement.User, error) {
		return service.ReactivateUser(c.Request.Context(), userID)
	})
}

func (s *Server) handleAdminUserStatusAction(c *gin.Context, action func(*usermanagement.UserLifecycleService, usermanagement.UserID) (*usermanagement.User, error)) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	user, err := action(usermanagement.NewUserLifecycleService(store, store), usermanagement.UserID(c.Param("id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": toUserResponse(user)})
}

func (s *Server) handleAdminBootstrap(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	// Bootstrap requires management-key authorization, not a user session.
	if auth, _ := c.Get("managementAuth"); auth != "management_key" {
		c.JSON(http.StatusForbidden, gin.H{"error": "bootstrap requires management key authorization"})
		return
	}
	var body struct {
		Username    string `json:"username"`
		Email       string `json:"email"`
		Password    string `json:"password"`
		DisplayName string `json:"display_name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	user, err := usermanagement.NewBootstrapService(store).CreateFirstAdmin(c.Request.Context(), usermanagement.BootstrapAdminRequest{
		ManagementAuthorized: true,
		Username:             body.Username,
		Email:                body.Email,
		Password:             body.Password,
		DisplayName:          body.DisplayName,
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user": toUserResponse(user)})
}

func toUserResponses(users []usermanagement.User) []userResponse {
	out := make([]userResponse, 0, len(users))
	for i := range users {
		out = append(out, toUserResponse(&users[i]))
	}
	return out
}

func intQuery(c *gin.Context, key string) int {
	value, err := strconv.Atoi(strings.TrimSpace(c.Query(key)))
	if err != nil || value < 0 {
		return 0
	}
	return value
}
