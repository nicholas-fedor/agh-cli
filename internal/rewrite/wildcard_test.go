// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
	mockAdguard "github.com/nicholas-fedor/agh-cli/pkg/adguard/mocks"
)

// TestWildcardAddUsesUniqueAnswersInSourceOrder verifies wildcard matching and creation.
func TestWildcardAddUsesUniqueAnswersInSourceOrder(t *testing.T) {
	t.Parallel()

	zoneRule := Rule{
		Domain:  new(rewriteTestDomain),
		Answer:  new(rewriteTestAnswer),
		Enabled: new(false),
	}
	subdomainRule := Rule{
		Domain:  new("sub." + rewriteTestDomain),
		Answer:  new(rewriteTestAnswer),
		Enabled: new(true),
	}
	ipv6Rule := Rule{
		Domain:  new(rewriteTestDomain),
		Answer:  new(rewriteTestIPv6Answer),
		Enabled: new(false),
	}
	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().ListRewriteRules(mock.Anything).Return([]adguard.RewriteRule{
		zoneRule.wireRule(),
		subdomainRule.wireRule(),
		ipv6Rule.wireRule(),
	}, nil).Once()
	service.EXPECT().AddRewriteRule(mock.Anything, adguard.RewriteRule{
		Domain:  new("*." + rewriteTestDomain),
		Answer:  new(rewriteTestAnswer),
		Enabled: new(true),
	}).Return(nil).Once()
	service.EXPECT().AddRewriteRule(mock.Anything, adguard.RewriteRule{
		Domain:  new("*." + rewriteTestDomain),
		Answer:  new(rewriteTestIPv6Answer),
		Enabled: new(true),
	}).Return(nil).Once()

	err := NewService(service).WildcardAdd(t.Context(), rewriteTestDomain)

	require.NoError(t, err)
}

// TestWildcardDeleteRemovesBareAndWildcardRules verifies deletion order and matching.
func TestWildcardDeleteRemovesBareAndWildcardRules(t *testing.T) {
	t.Parallel()

	zoneRule := Rule{Domain: new(rewriteTestDomain), Answer: new(rewriteTestAnswer)}
	wildcardRule := Rule{
		Domain: new("*." + rewriteTestDomain),
		Answer: new(rewriteTestAnswer),
	}
	subdomainRule := Rule{Domain: new("sub." + rewriteTestDomain)}
	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().ListRewriteRules(mock.Anything).Return([]adguard.RewriteRule{
		zoneRule.wireRule(),
		wildcardRule.wireRule(),
		subdomainRule.wireRule(),
	}, nil).Once()
	service.EXPECT().DeleteRewriteRule(mock.Anything, zoneRule.wireRule()).Return(nil).Once()
	service.EXPECT().DeleteRewriteRule(mock.Anything, wildcardRule.wireRule()).Return(nil).Once()

	err := NewService(service).WildcardDelete(t.Context(), rewriteTestDomain)

	require.NoError(t, err)
}

// TestWildcardOperationsPropagateErrors verifies failures remain matchable.
func TestWildcardOperationsPropagateErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("wildcard unavailable")
	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().ListRewriteRules(mock.Anything).Return(nil, wantErr).Once()
	service.EXPECT().ListRewriteRules(mock.Anything).Return(nil, wantErr).Once()

	rewrite := NewService(service)
	addErr := rewrite.WildcardAdd(t.Context(), rewriteTestDomain)
	deleteErr := rewrite.WildcardDelete(t.Context(), rewriteTestDomain)

	require.ErrorIs(t, addErr, wantErr)
	require.ErrorIs(t, deleteErr, wantErr)
}
