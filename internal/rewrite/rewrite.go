// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"context"
	"errors"
	"fmt"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// Rule contains the presence-aware values of one DNS rewrite rule.
type Rule struct {
	// Domain is the rewritten domain when present.
	Domain *string `json:"domain" yaml:"domain"`
	// Answer is the rewritten answer when present.
	Answer *string `json:"answer" yaml:"answer"`
	// Enabled preserves an explicit enabled state when present.
	Enabled *bool `json:"enabled" yaml:"enabled"`
}

// RuleRequest contains the command values used to mutate one rewrite rule.
type RuleRequest struct {
	// Domain is the rewritten domain.
	Domain string
	// Answer is the rewritten answer.
	Answer string
	// Enabled controls whether the rule is active.
	Enabled bool
}

// Settings contains the global DNS rewrite settings.
type Settings struct {
	// Enabled reports whether DNS rewrites are applied.
	Enabled bool
}

// Service executes rewrite-management use cases through the public AdGuard service.
type Service struct {
	rewrite adguard.RewriteService
}

// errNilSettings reports an invalid successful response without settings data.
var errNilSettings = errors.New("rewrite service returned nil settings")

// NewService creates a rewrite-management use-case service.
//
// Parameters:
//   - rewrite: public AdGuard rewrite service backing the use cases.
//
// Returns:
//   - *Service: use-case service wrapping the public service.
func NewService(rewrite adguard.RewriteService) *Service {
	return &Service{rewrite: rewrite}
}

// Add creates one DNS rewrite rule.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: rewrite values sent to AdGuard Home.
//
// Returns:
//   - error: a wrapped rule-creation error.
func (s *Service) Add(ctx context.Context, request RuleRequest) error {
	err := s.rewrite.AddRewriteRule(ctx, request.wireRule())
	if err != nil {
		return fmt.Errorf("add rewrite rule: %w", err)
	}

	return nil
}

// Delete removes one DNS rewrite rule.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: rewrite values identifying the rule to remove.
//
// Returns:
//   - error: a wrapped rule-deletion error.
func (s *Service) Delete(ctx context.Context, request RuleRequest) error {
	err := s.rewrite.DeleteRewriteRule(ctx, request.wireRule())
	if err != nil {
		return fmt.Errorf("delete rewrite rule: %w", err)
	}

	return nil
}

// GetSettings retrieves the global DNS rewrite settings.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//
// Returns:
//   - Settings: the global rewrite settings.
//   - error: a wrapped settings error, or errNilSettings for a successful
//     response without settings data.
func (s *Service) GetSettings(ctx context.Context) (Settings, error) {
	wireSettings, err := s.rewrite.GetRewriteSettings(ctx)
	if err != nil {
		return Settings{}, fmt.Errorf("get rewrite settings: %w", err)
	}
	if wireSettings == nil {
		return Settings{}, errNilSettings
	}

	return Settings{Enabled: wireSettings.Enabled}, nil
}

// List retrieves DNS rewrite rules and shapes them for domain consumers.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//
// Returns:
//   - []Rule: presence-aware domain rules in service order.
//   - error: a wrapped rule-listing error.
func (s *Service) List(ctx context.Context) ([]Rule, error) {
	wireRules, err := s.rewrite.ListRewriteRules(ctx)
	if err != nil {
		return nil, fmt.Errorf("list rewrite rules: %w", err)
	}

	return shapeRules(wireRules), nil
}

// Update replaces one DNS rewrite rule while preserving a zero target value.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: rewrite values sent to AdGuard Home.
//
// Returns:
//   - error: a wrapped rule-update error.
func (s *Service) Update(ctx context.Context, request RuleRequest) error {
	update := adguard.RewriteUpdate{Update: request.wireRule()}

	err := s.rewrite.UpdateRewriteRule(ctx, update)
	if err != nil {
		return fmt.Errorf("update rewrite rule: %w", err)
	}

	return nil
}

// UpdateSettings applies the global DNS rewrite settings.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - settings: rewrite settings sent to AdGuard Home.
//
// Returns:
//   - error: a wrapped settings-update error.
func (s *Service) UpdateSettings(ctx context.Context, settings Settings) error {
	wireSettings := adguard.RewriteSettings{Enabled: settings.Enabled}

	err := s.rewrite.UpdateRewriteSettings(ctx, wireSettings)
	if err != nil {
		return fmt.Errorf("update rewrite settings: %w", err)
	}

	return nil
}

// wireRule shapes a mutation request while preserving explicit values.
//
// Returns:
//   - adguard.RewriteRule: the wire rule carrying every request value.
func (r RuleRequest) wireRule() adguard.RewriteRule {
	return adguard.RewriteRule{
		Domain:  new(r.Domain),
		Answer:  new(r.Answer),
		Enabled: new(r.Enabled),
	}
}

// shapeRules converts wire rules into presence-aware domain rules.
//
// Parameters:
//   - wireRules: wire rules; nil stays nil.
//
// Returns:
//   - []Rule: domain rules with copied optional values.
//   - nil: returned unchanged for absent input.
func shapeRules(wireRules []adguard.RewriteRule) []Rule {
	if wireRules == nil {
		return nil
	}

	rules := make([]Rule, 0, len(wireRules))
	for _, wireRule := range wireRules {
		rules = append(rules, Rule{
			Domain:  clonePointer(wireRule.Domain),
			Answer:  clonePointer(wireRule.Answer),
			Enabled: clonePointer(wireRule.Enabled),
		})
	}

	return rules
}

// clonePointer copies one optional value.
//
// Parameters:
//   - value: optional value to copy.
//
// Returns:
//   - *T: an independent copy, or nil for absent input.
func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}

	return new(*value)
}
