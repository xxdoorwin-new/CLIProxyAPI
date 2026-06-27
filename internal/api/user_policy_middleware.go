package api

import (
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/usermanagement"
	"github.com/tidwall/gjson"
)

func UserModelPolicyMiddleware(policy *usermanagement.ModelPolicyService) gin.HandlerFunc {
	return func(c *gin.Context) {
		if policy == nil {
			c.Next()
			return
		}
		userID, keyID := userPrincipalFromContext(c)
		if userID == "" {
			c.Next()
			return
		}
		model, err := requestModelName(c)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid request body"})
			return
		}
		if model == "" {
			c.Next()
			return
		}
		allowed, _, err := policy.IsModelAllowed(c.Request.Context(), userID, keyID, model)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "model policy check failed"})
			return
		}
		if !allowed {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "model is not allowed for this user"})
			return
		}
		c.Set("userRequestedModel", model)
		c.Next()
	}
}

func userPrincipalFromContext(c *gin.Context) (usermanagement.UserID, usermanagement.APIKeyID) {
	raw, ok := c.Get("accessMetadata")
	if !ok {
		return "", ""
	}
	metadata, ok := raw.(map[string]string)
	if !ok {
		return "", ""
	}
	userID := strings.TrimSpace(metadata["user_id"])
	keyID := strings.TrimSpace(metadata["api_key_id"])
	if userID == "" {
		return "", ""
	}
	return usermanagement.UserID(userID), usermanagement.APIKeyID(keyID)
}

func requestModelName(c *gin.Context) (string, error) {
	if model := modelFromPath(c.Request.URL.Path); model != "" {
		return model, nil
	}
	if c.Request.Body == nil {
		return "", nil
	}
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		return "", err
	}
	c.Request.Body = io.NopCloser(bytes.NewReader(body))
	if len(bytes.TrimSpace(body)) == 0 {
		return "", nil
	}
	if !gjson.ValidBytes(body) {
		return "", nil
	}
	if result := gjson.GetBytes(body, "model"); result.Exists() && result.Type == gjson.String {
		return strings.TrimSpace(result.String()), nil
	}
	return "", nil
}

func modelFromPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	idx := strings.Index(path, "/models/")
	if idx < 0 {
		return ""
	}
	model := path[idx+len("/models/"):]
	if slash := strings.Index(model, "/"); slash >= 0 {
		model = model[:slash]
	}
	if colon := strings.Index(model, ":"); colon >= 0 {
		model = model[:colon]
	}
	return strings.TrimSpace(strings.TrimPrefix(model, "models/"))
}
