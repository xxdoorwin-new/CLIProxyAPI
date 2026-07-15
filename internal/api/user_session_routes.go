package api

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
)

type userResponse struct {
	ID          string `json:"id"`
	Username    string `json:"username"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name,omitempty"`
	Status      string `json:"status"`
	Role        string `json:"role"`
}

type sessionResponse struct {
	Token     string       `json:"token,omitempty"`
	ExpiresAt time.Time    `json:"expires_at,omitempty"`
	User      userResponse `json:"user"`
}

type quotaSummaryResponse struct {
	UserID           string    `json:"user_id"`
	Period           string    `json:"period"`
	LimitCredits     int64     `json:"limit_credits"`
	UsedCredits      int64     `json:"used_credits"`
	RemainingCredits int64     `json:"remaining_credits"`
	PeriodStart      time.Time `json:"period_start"`
	PeriodEnd        time.Time `json:"period_end"`
}

type usageLedgerResponse struct {
	ID              string    `json:"id"`
	UserID          string    `json:"user_id"`
	APIKeyID        string    `json:"api_key_id"`
	RequestID       string    `json:"request_id"`
	Provider        string    `json:"provider"`
	Model           string    `json:"model"`
	ModelAlias      string    `json:"model_alias"`
	InputTokens     int64     `json:"input_tokens"`
	OutputTokens    int64     `json:"output_tokens"`
	CachedTokens    int64     `json:"cached_tokens"`
	ReasoningTokens int64     `json:"reasoning_tokens"`
	ImageCount      int64     `json:"image_count"`
	CreditCost      int64     `json:"credit_cost"`
	Status          string    `json:"status"`
	ErrorCode       string    `json:"error_code,omitempty"`
	LatencyMillis   int64     `json:"latency_millis"`
	CreatedAt       time.Time `json:"created_at"`
}

type usageSummaryResponse struct {
	Quota       quotaSummaryResponse  `json:"quota"`
	RecentUsage []usageLedgerResponse `json:"recent_usage"`
	Total       int64                 `json:"total"`
}

func (s *Server) registerUserSessionRoutes() {
	group := s.engine.Group("/v0/user")
	group.POST("/register", s.handleUserRegister)
	group.POST("/login", s.handleUserLogin)
	group.GET("/session", s.handleUserSession)
	group.POST("/logout", s.handleUserLogout)
	group.GET("/profile", s.handleUserProfile)
	group.POST("/password", s.handleUserChangePassword)
	group.GET("/api-keys", s.handleUserAPIKeys)
	group.GET("/models", s.handleUserAllowedModels)
	group.GET("/quota", s.handleUserQuotaSummary)
	group.GET("/usage", s.handleUserUsage)
}

func (s *Server) handleUserRegister(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	if s.cfg == nil || !s.cfg.UserManagement.Registration.Enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "registration is disabled"})
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
	user, err := usermanagement.NewRegistrationService(store).Register(c.Request.Context(), usermanagement.RegisterUserRequest{
		Username:    body.Username,
		Email:       body.Email,
		Password:    body.Password,
		DisplayName: body.DisplayName,
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusCreated, gin.H{"user": toUserResponse(user)})
}

func (s *Server) handleUserLogin(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	var body struct {
		Identity string `json:"identity"`
		Password string `json:"password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	credential, err := usermanagement.NewLoginService(store, store).Login(c.Request.Context(), usermanagement.LoginRequest{
		Identity: body.Identity,
		Password: body.Password,
		TTL:      s.userSessionTTL(),
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	user, err := store.GetUser(c.Request.Context(), credential.Session.UserID)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"session": sessionResponse{
		Token:     credential.Token,
		ExpiresAt: credential.Session.ExpiresAt,
		User:      toUserResponse(user),
	}})
}

func (s *Server) handleUserSession(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	principal, ok := s.resolveUserSession(c, store)
	if !ok {
		return
	}
	c.JSON(http.StatusOK, gin.H{"session": sessionResponse{
		User: userResponse{
			ID:       string(principal.UserID),
			Username: principal.Username,
			Email:    principal.Email,
			Status:   string(principal.Status),
			Role:     string(principal.Role),
		},
	}})
}

func (s *Server) handleUserLogout(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	token := userSessionTokenFromRequest(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user session"})
		return
	}
	if err := usermanagement.NewSessionService(store, store).RevokeSession(c.Request.Context(), token); err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleUserProfile(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	principal, ok := s.resolveUserSession(c, store)
	if !ok {
		return
	}
	user, err := store.GetUser(c.Request.Context(), principal.UserID)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"user": toUserResponse(user)})
}

func (s *Server) handleUserChangePassword(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	principal, ok := s.resolveUserSession(c, store)
	if !ok {
		return
	}
	var body struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	user, err := store.GetUser(c.Request.Context(), principal.UserID)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	if !usermanagement.VerifyPassword(body.CurrentPassword, user.PasswordHash) {
		writeUserManagementError(c, usermanagement.ErrUnauthorized)
		return
	}
	hash, err := usermanagement.HashPassword(body.NewPassword)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	if _, err = store.UpdateUser(c.Request.Context(), principal.UserID, usermanagement.UpdateUserParams{PasswordHash: hash}); err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (s *Server) handleUserAPIKeys(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	principal, ok := s.resolveUserSession(c, store)
	if !ok {
		return
	}
	keys, err := usermanagement.NewUserAPIKeyService(store, store, s.configuredAPIKeys()).ListKeyMetadataByUser(c.Request.Context(), principal.UserID)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	out := make([]userAPIKeyResponse, 0, len(keys))
	for i := range keys {
		entry := toAPIKeyMetadataResponse(keys[i])
		if keys[i].ConfiguredKeyPresent {
			entry.APIKey = s.configuredAPIKeyByFingerprint(keys[i].ConfiguredKeyFingerprint)
		}
		out = append(out, entry)
	}
	c.JSON(http.StatusOK, gin.H{"api_keys": out})
}

func (s *Server) handleUserAllowedModels(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	principal, ok := s.resolveUserSession(c, store)
	if !ok {
		return
	}
	policy, err := usermanagement.NewModelPolicyService(store).ResolveForUser(c.Request.Context(), principal.UserID)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"model_policy": toResolvedModelPolicyResponse(policy)})
}

func (s *Server) handleUserQuotaSummary(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	principal, ok := s.resolveUserSession(c, store)
	if !ok {
		return
	}
	summary, err := usermanagement.NewQuotaService(store, store).Summary(c.Request.Context(), principal.UserID)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"quota": toQuotaSummaryResponse(summary)})
}

func (s *Server) handleUserUsage(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	principal, ok := s.resolveUserSession(c, store)
	if !ok {
		return
	}
	summary, err := usermanagement.NewUsageSummaryService(store, store, store).Summary(c.Request.Context(), usermanagement.UsageSummaryQuery{
		UserID: principal.UserID,
		Limit:  intQuery(c, "limit"),
		Offset: intQuery(c, "offset"),
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"usage": toUsageSummaryResponse(summary)})
}

func (s *Server) currentUserStore(c *gin.Context) (*usermanagement.SQLiteStore, bool) {
	if s == nil || s.cfg == nil || !s.cfg.UserManagement.Enabled {
		c.JSON(http.StatusNotFound, gin.H{"error": "user management is disabled"})
		return nil, false
	}
	s.userManagementMu.RLock()
	store := s.userStore
	s.userManagementMu.RUnlock()
	if store == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "user management store is not available"})
		return nil, false
	}
	return store, true
}

func (s *Server) resolveUserSession(c *gin.Context, store *usermanagement.SQLiteStore) (*usermanagement.Principal, bool) {
	token := userSessionTokenFromRequest(c)
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing user session"})
		return nil, false
	}
	principal, err := usermanagement.NewSessionService(store, store).ResolvePrincipal(c.Request.Context(), token)
	if err != nil {
		writeUserManagementError(c, err)
		return nil, false
	}
	return principal, true
}

func (s *Server) userSessionTTL() time.Duration {
	if s == nil || s.cfg == nil {
		return 0
	}
	raw := strings.TrimSpace(s.cfg.UserManagement.Sessions.TTL)
	if raw == "" {
		return 0
	}
	ttl, err := time.ParseDuration(raw)
	if err != nil {
		return 0
	}
	return ttl
}

func userSessionTokenFromRequest(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if token := strings.TrimSpace(c.GetHeader("X-User-Session")); token != "" {
		return token
	}
	auth := strings.TrimSpace(c.GetHeader("Authorization"))
	if auth == "" {
		return ""
	}
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) == 2 && strings.EqualFold(parts[0], "bearer") {
		return strings.TrimSpace(parts[1])
	}
	return auth
}

func toUserResponse(user *usermanagement.User) userResponse {
	if user == nil {
		return userResponse{}
	}
	return userResponse{
		ID:          string(user.ID),
		Username:    user.Username,
		Email:       user.Email,
		DisplayName: user.DisplayName,
		Status:      string(user.Status),
		Role:        string(user.Role),
	}
}

func toQuotaSummaryResponse(summary *usermanagement.QuotaSummary) quotaSummaryResponse {
	if summary == nil {
		return quotaSummaryResponse{}
	}
	return quotaSummaryResponse{
		UserID:           string(summary.UserID),
		Period:           string(summary.Period),
		LimitCredits:     summary.LimitCredits,
		UsedCredits:      summary.UsedCredits,
		RemainingCredits: summary.RemainingCredits,
		PeriodStart:      summary.PeriodStart,
		PeriodEnd:        summary.PeriodEnd,
	}
}

func toUsageSummaryResponse(summary *usermanagement.UsageSummary) usageSummaryResponse {
	if summary == nil {
		return usageSummaryResponse{}
	}
	out := usageSummaryResponse{
		Quota:       toQuotaSummaryResponse(&summary.Quota),
		RecentUsage: make([]usageLedgerResponse, 0, len(summary.RecentUsage)),
		Total:       summary.Total,
	}
	for i := range summary.RecentUsage {
		out.RecentUsage = append(out.RecentUsage, toUsageLedgerResponse(&summary.RecentUsage[i]))
	}
	return out
}

func toUsageLedgerResponse(row *usermanagement.UsageLedgerRow) usageLedgerResponse {
	if row == nil {
		return usageLedgerResponse{}
	}
	return usageLedgerResponse{
		ID:              string(row.ID),
		UserID:          string(row.UserID),
		APIKeyID:        string(row.APIKeyID),
		RequestID:       row.RequestID,
		Provider:        row.Provider,
		Model:           row.Model,
		ModelAlias:      row.ModelAlias,
		InputTokens:     row.InputTokens,
		OutputTokens:    row.OutputTokens,
		CachedTokens:    row.CachedTokens,
		ReasoningTokens: row.ReasoningTokens,
		ImageCount:      row.ImageCount,
		CreditCost:      row.CreditCost,
		Status:          string(row.Status),
		ErrorCode:       row.ErrorCode,
		LatencyMillis:   row.LatencyMillis,
		CreatedAt:       row.CreatedAt,
	}
}

func writeUserManagementError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, usermanagement.ErrInvalid):
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	case errors.Is(err, usermanagement.ErrUnauthorized):
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
	case errors.Is(err, usermanagement.ErrForbidden):
		c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	case errors.Is(err, usermanagement.ErrNotFound):
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
	case errors.Is(err, usermanagement.ErrConflict):
		c.JSON(http.StatusConflict, gin.H{"error": "conflict"})
	case errors.Is(err, usermanagement.ErrAlreadyExists):
		c.JSON(http.StatusConflict, gin.H{"error": "already exists"})
	default:
		c.JSON(http.StatusInternalServerError, gin.H{"error": "user management operation failed"})
	}
}
