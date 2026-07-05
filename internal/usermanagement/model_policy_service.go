package usermanagement

import (
	"context"
	"errors"
	"strings"
)

type ModelPolicyService struct {
	policies ModelPolicyStore
}

type ResolvedModelPolicy struct {
	SubjectType PolicySubjectType
	SubjectID   string
	AllowAll    bool
	Models      []string
}

func NewModelPolicyService(policies ModelPolicyStore) *ModelPolicyService {
	return &ModelPolicyService{policies: policies}
}

func (s *ModelPolicyService) SetUserModels(ctx context.Context, userID UserID, allowAll bool, models []string) (*ModelPolicy, error) {
	return s.setPolicy(ctx, SetModelPolicyParams{
		SubjectType: PolicySubjectUser,
		SubjectID:   string(userID),
		AllowAll:    allowAll,
		Models:      NormalizeModelList(models),
	})
}

func (s *ModelPolicyService) SetAPIKeyModels(ctx context.Context, keyID APIKeyID, allowAll bool, models []string) (*ModelPolicy, error) {
	return s.setPolicy(ctx, SetModelPolicyParams{
		SubjectType: PolicySubjectAPIKey,
		SubjectID:   string(keyID),
		AllowAll:    allowAll,
		Models:      NormalizeModelList(models),
	})
}

func (s *ModelPolicyService) ResolveForUser(ctx context.Context, userID UserID) (*ResolvedModelPolicy, error) {
	return s.resolve(ctx, PolicySubjectUser, string(userID))
}

func (s *ModelPolicyService) ResolveForAPIKey(ctx context.Context, userID UserID, keyID APIKeyID) (*ResolvedModelPolicy, error) {
	if keyID != "" {
		policy, err := s.resolve(ctx, PolicySubjectAPIKey, string(keyID))
		if err != nil {
			return nil, err
		}
		if policy.SubjectID != "" {
			return policy, nil
		}
	}
	return s.ResolveForUser(ctx, userID)
}

func (s *ModelPolicyService) IsModelAllowed(ctx context.Context, userID UserID, keyID APIKeyID, model string) (bool, *ResolvedModelPolicy, error) {
	policy, err := s.ResolveForAPIKey(ctx, userID, keyID)
	if err != nil {
		return false, nil, err
	}
	// AllowAll explicitly set, or no models restriction configured (empty list) — allow everything.
	if policy.AllowAll || len(policy.Models) == 0 {
		return true, policy, nil
	}
	model = strings.TrimSpace(model)
	if model == "" {
		return false, policy, nil
	}
	for _, allowed := range policy.Models {
		if allowed == model {
			return true, policy, nil
		}
	}
	return false, policy, nil
}

func (s *ModelPolicyService) setPolicy(ctx context.Context, params SetModelPolicyParams) (*ModelPolicy, error) {
	if s == nil || s.policies == nil {
		return nil, ErrInvalid
	}
	return s.policies.SetModelPolicy(ctx, params)
}

func (s *ModelPolicyService) resolve(ctx context.Context, subjectType PolicySubjectType, subjectID string) (*ResolvedModelPolicy, error) {
	if s == nil || s.policies == nil {
		return nil, ErrInvalid
	}
	policy, err := s.policies.GetModelPolicy(ctx, subjectType, subjectID)
	if errors.Is(err, ErrNotFound) {
		// No explicit policy set — default to allow all models so that users
		// without a configured policy can still use the API.
		return &ResolvedModelPolicy{
			SubjectType: subjectType,
			SubjectID:   "",
			AllowAll:    true,
			Models:      nil,
		}, nil
	}
	if err != nil {
		return nil, err
	}
	return &ResolvedModelPolicy{
		SubjectType: policy.SubjectType,
		SubjectID:   policy.SubjectID,
		AllowAll:    policy.AllowAll,
		Models:      append([]string(nil), policy.Models...),
	}, nil
}
