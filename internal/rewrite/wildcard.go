// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"context"
	"fmt"
	"strings"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// WildcardAdd creates wildcard rules for each unique answer under a zone.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - zone: DNS zone covered by the wildcard rules.
//
// Returns:
//   - error: a wrapped listing or rule-creation error.
func (s *Service) WildcardAdd(ctx context.Context, zone string) error {
	rules, err := s.List(ctx)
	if err != nil {
		return fmt.Errorf("list rewrite rules for wildcard add: %w", err)
	}

	for _, rule := range wildcardRules(rules, zone) {
		err = s.rewrite.AddRewriteRule(ctx, rule.wireRule())
		if err != nil {
			return fmt.Errorf(
				"add wildcard %s -> %s: %w",
				ruleDomain(rule),
				ruleAnswer(rule),
				err,
			)
		}
	}

	return nil
}

// WildcardDelete removes bare-zone and wildcard rules for a zone in source order.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - zone: DNS zone whose bare and wildcard rules are removed.
//
// Returns:
//   - error: a wrapped listing or rule-deletion error.
func (s *Service) WildcardDelete(ctx context.Context, zone string) error {
	rules, err := s.List(ctx)
	if err != nil {
		return fmt.Errorf("list rewrite rules for wildcard delete: %w", err)
	}

	for _, rule := range rules {
		domain := ruleDomain(rule)
		if domain != zone && domain != "*."+zone {
			continue
		}

		err = s.rewrite.DeleteRewriteRule(ctx, rule.wireRule())
		if err != nil {
			return fmt.Errorf("delete %s: %w", domain, err)
		}
	}

	return nil
}

// wildcardRules returns unique wildcard rules in source order.
//
// Parameters:
//   - rules: domain rules inspected for matching answers.
//   - zone: DNS zone whose subdomains produce wildcard rules.
//
// Returns:
//   - []Rule: one enabled wildcard rule per unique answer.
func wildcardRules(rules []Rule, zone string) []Rule {
	seen := make(map[string]struct{}, len(rules))
	wildcards := make([]Rule, 0, len(rules))

	for _, rule := range rules {
		answer := ruleAnswer(rule)
		if !isSubdomain(ruleDomain(rule), zone) {
			continue
		}
		if _, exists := seen[answer]; exists {
			continue
		}

		seen[answer] = struct{}{}

		wildcards = append(wildcards, Rule{
			Domain:  new("*." + zone),
			Answer:  clonePointer(rule.Answer),
			Enabled: new(true),
		})
	}

	return wildcards
}

// wireRule preserves the optional fields of a domain rule.
//
// Returns:
//   - adguard.RewriteRule: the wire rule carrying copied optional values.
func (r Rule) wireRule() adguard.RewriteRule {
	return adguard.RewriteRule{
		Domain:  clonePointer(r.Domain),
		Answer:  clonePointer(r.Answer),
		Enabled: clonePointer(r.Enabled),
	}
}

// isSubdomain reports whether domain equals zone or is below zone.
//
// Parameters:
//   - domain: domain name to test.
//   - zone: DNS zone name to test against.
//
// Returns:
//   - bool: true when the domain is the zone or a subdomain of it.
func isSubdomain(domain, zone string) bool {
	return domain == zone || strings.HasSuffix(domain, "."+zone)
}
