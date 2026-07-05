package api

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
)

type modelPolicyResponse struct {
	SubjectType string    `json:"subject_type"`
	SubjectID   string    `json:"subject_id"`
	AllowAll    bool      `json:"allow_all"`
	Models      []string  `json:"models"`
	CreatedAt   time.Time `json:"created_at,omitempty"`
	UpdatedAt   time.Time `json:"updated_at,omitempty"`
}

type quotaPolicyResponse struct {
	UserID       string    `json:"user_id"`
	Period       string    `json:"period"`
	LimitCredits int64     `json:"limit_credits"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

type pricingRuleResponse struct {
	Model                            string    `json:"model"`
	InputCreditsPerMillionTokens     int64     `json:"input_credits_per_million_tokens"`
	OutputCreditsPerMillionTokens    int64     `json:"output_credits_per_million_tokens"`
	CachedCreditsPerMillionTokens    int64     `json:"cached_credits_per_million_tokens"`
	ReasoningCreditsPerMillionTokens int64     `json:"reasoning_credits_per_million_tokens"`
	ImageCredits                     int64     `json:"image_credits"`
	RequestCredits                   int64     `json:"request_credits"`
	CreatedAt                        time.Time `json:"created_at"`
	UpdatedAt                        time.Time `json:"updated_at"`
}

func (s *Server) handleAdminGetUserModelPolicy(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	policy, err := usermanagement.NewModelPolicyService(store).ResolveForUser(c.Request.Context(), usermanagement.UserID(c.Param("id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"model_policy": toResolvedModelPolicyResponse(policy)})
}

func (s *Server) handleAdminSetUserModelPolicy(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	var body struct {
		AllowAll bool     `json:"allow_all"`
		Models   []string `json:"models"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	policy, err := usermanagement.NewModelPolicyService(store).SetUserModels(c.Request.Context(), usermanagement.UserID(c.Param("id")), body.AllowAll, body.Models)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"model_policy": toModelPolicyResponse(policy)})
}

func (s *Server) handleAdminGetAPIKeyModelPolicy(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	if !s.ensureUserAPIKeyOwner(c, store) {
		return
	}
	policy, err := usermanagement.NewModelPolicyService(store).ResolveForAPIKey(c.Request.Context(), usermanagement.UserID(c.Param("id")), usermanagement.APIKeyID(c.Param("key_id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"model_policy": toResolvedModelPolicyResponse(policy)})
}

func (s *Server) handleAdminSetAPIKeyModelPolicy(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	if !s.ensureUserAPIKeyOwner(c, store) {
		return
	}
	var body struct {
		AllowAll bool     `json:"allow_all"`
		Models   []string `json:"models"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	policy, err := usermanagement.NewModelPolicyService(store).SetAPIKeyModels(c.Request.Context(), usermanagement.APIKeyID(c.Param("key_id")), body.AllowAll, body.Models)
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"model_policy": toModelPolicyResponse(policy)})
}

func (s *Server) handleAdminGetUserQuotaPolicy(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	policy, err := store.GetQuotaPolicy(c.Request.Context(), usermanagement.UserID(c.Param("id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"quota_policy": toQuotaPolicyResponse(policy)})
}

func (s *Server) handleAdminSetUserQuotaPolicy(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	var body struct {
		Period       string `json:"period"`
		LimitCredits int64  `json:"limit_credits"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	period := usermanagement.QuotaPeriod(strings.TrimSpace(body.Period))
	if period == "" {
		period = usermanagement.QuotaPeriodMonthly
	}
	policy, err := usermanagement.NewQuotaService(store, store).SetPolicy(c.Request.Context(), usermanagement.SetQuotaPolicyParams{
		UserID:       usermanagement.UserID(c.Param("id")),
		Period:       period,
		LimitCredits: body.LimitCredits,
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"quota_policy": toQuotaPolicyResponse(policy)})
}

func (s *Server) handleAdminListPricingRules(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	rules, err := store.ListPricingRules(c.Request.Context())
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	out := make([]pricingRuleResponse, 0, len(rules))
	for i := range rules {
		out = append(out, toPricingRuleResponse(&rules[i]))
	}
	c.JSON(http.StatusOK, gin.H{"pricing_rules": out})
}

func (s *Server) handleAdminSetPricingRule(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	var body struct {
		Model                            string `json:"model"`
		InputCreditsPerMillionTokens     int64  `json:"input_credits_per_million_tokens"`
		OutputCreditsPerMillionTokens    int64  `json:"output_credits_per_million_tokens"`
		CachedCreditsPerMillionTokens    int64  `json:"cached_credits_per_million_tokens"`
		ReasoningCreditsPerMillionTokens int64  `json:"reasoning_credits_per_million_tokens"`
		ImageCredits                     int64  `json:"image_credits"`
		RequestCredits                   int64  `json:"request_credits"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid body"})
		return
	}
	rule, err := usermanagement.NewPricingService(store).SetRule(c.Request.Context(), usermanagement.SetPricingRuleParams{
		Model:                            body.Model,
		InputCreditsPerMillionTokens:     body.InputCreditsPerMillionTokens,
		OutputCreditsPerMillionTokens:    body.OutputCreditsPerMillionTokens,
		CachedCreditsPerMillionTokens:    body.CachedCreditsPerMillionTokens,
		ReasoningCreditsPerMillionTokens: body.ReasoningCreditsPerMillionTokens,
		ImageCredits:                     body.ImageCredits,
		RequestCredits:                   body.RequestCredits,
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"pricing_rule": toPricingRuleResponse(rule)})
}

func (s *Server) handleAdminDeletePricingRule(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	if err := store.DeletePricingRule(c.Request.Context(), c.Query("model")); err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func toResolvedModelPolicyResponse(policy *usermanagement.ResolvedModelPolicy) modelPolicyResponse {
	if policy == nil {
		return modelPolicyResponse{Models: []string{}}
	}
	return modelPolicyResponse{
		SubjectType: string(policy.SubjectType),
		SubjectID:   policy.SubjectID,
		AllowAll:    policy.AllowAll,
		Models:      append([]string(nil), policy.Models...),
	}
}

func toModelPolicyResponse(policy *usermanagement.ModelPolicy) modelPolicyResponse {
	if policy == nil {
		return modelPolicyResponse{Models: []string{}}
	}
	return modelPolicyResponse{
		SubjectType: string(policy.SubjectType),
		SubjectID:   policy.SubjectID,
		AllowAll:    policy.AllowAll,
		Models:      append([]string(nil), policy.Models...),
		CreatedAt:   policy.CreatedAt,
		UpdatedAt:   policy.UpdatedAt,
	}
}

func toQuotaPolicyResponse(policy *usermanagement.QuotaPolicy) quotaPolicyResponse {
	if policy == nil {
		return quotaPolicyResponse{}
	}
	return quotaPolicyResponse{
		UserID:       string(policy.UserID),
		Period:       string(policy.Period),
		LimitCredits: policy.LimitCredits,
		CreatedAt:    policy.CreatedAt,
		UpdatedAt:    policy.UpdatedAt,
	}
}

func toPricingRuleResponse(rule *usermanagement.PricingRule) pricingRuleResponse {
	if rule == nil {
		return pricingRuleResponse{}
	}
	return pricingRuleResponse{
		Model:                            rule.Model,
		InputCreditsPerMillionTokens:     rule.InputCreditsPerMillionTokens,
		OutputCreditsPerMillionTokens:    rule.OutputCreditsPerMillionTokens,
		CachedCreditsPerMillionTokens:    rule.CachedCreditsPerMillionTokens,
		ReasoningCreditsPerMillionTokens: rule.ReasoningCreditsPerMillionTokens,
		ImageCredits:                     rule.ImageCredits,
		RequestCredits:                   rule.RequestCredits,
		CreatedAt:                        rule.CreatedAt,
		UpdatedAt:                        rule.UpdatedAt,
	}
}

func (s *Server) handleAdminGetUserQuotaSummary(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	summary, err := usermanagement.NewQuotaService(store, store).Summary(c.Request.Context(), usermanagement.UserID(c.Param("id")))
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"quota": toQuotaSummaryResponse(summary)})
}

func (s *Server) handleAdminGetUserUsage(c *gin.Context) {
	store, ok := s.currentUserStore(c)
	if !ok {
		return
	}
	summary, err := usermanagement.NewUsageSummaryService(store, store, store).Summary(c.Request.Context(), usermanagement.UsageSummaryQuery{
		UserID: usermanagement.UserID(c.Param("id")),
		Limit:  intQuery(c, "limit"),
		Offset: intQuery(c, "offset"),
	})
	if err != nil {
		writeUserManagementError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"usage": toUsageSummaryResponse(summary)})
}
