// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
	mockAdguard "github.com/nicholas-fedor/agh-cli/pkg/adguard/mocks"
)

// TestServiceListShapesRulePresence verifies optional response values remain distinguishable.
func TestServiceListShapesRulePresence(t *testing.T) {
	t.Parallel()

	emptyDomain := ""
	wireRules := []adguard.RewriteRule{
		{Domain: new(rewriteTestDomain), Answer: new(rewriteTestAnswer), Enabled: new(false)},
		{Domain: &emptyDomain, Answer: nil, Enabled: nil},
	}
	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().ListRewriteRules(mock.Anything).Return(wireRules, nil).Once()

	rules, err := NewService(service).List(t.Context())

	require.NoError(t, err)
	require.Len(t, rules, 2)
	assert.Equal(t, rewriteTestDomain, *rules[0].Domain)
	assert.Equal(t, rewriteTestAnswer, *rules[0].Answer)
	assert.False(t, *rules[0].Enabled)
	assert.Equal(t, emptyDomain, *rules[1].Domain)
	assert.Nil(t, rules[1].Answer)
	assert.Nil(t, rules[1].Enabled)
}

// TestServiceMutationsPreserveExplicitValues verifies request presence and zero update target.
func TestServiceMutationsPreserveExplicitValues(t *testing.T) {
	t.Parallel()

	request := RuleRequest{Domain: rewriteTestDomain, Answer: rewriteTestAnswer, Enabled: false}
	wireRule := adguard.RewriteRule{
		Domain:  new(rewriteTestDomain),
		Answer:  new(rewriteTestAnswer),
		Enabled: new(false),
	}
	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().AddRewriteRule(mock.Anything, wireRule).Return(nil).Once()
	service.EXPECT().DeleteRewriteRule(mock.Anything, wireRule).Return(nil).Once()
	service.EXPECT().UpdateRewriteRule(mock.Anything, adguard.RewriteUpdate{Update: wireRule}).Return(nil).Once()

	rewrite := NewService(service)

	require.NoError(t, rewrite.Add(t.Context(), request))
	require.NoError(t, rewrite.Delete(t.Context(), request))
	require.NoError(t, rewrite.Update(t.Context(), request))
}

// TestServiceSettingsPreserveExplicitFalse verifies required false settings values.
func TestServiceSettingsPreserveExplicitFalse(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().GetRewriteSettings(mock.Anything).Return(&adguard.RewriteSettings{
		Enabled: false,
	}, nil).Once()
	service.EXPECT().UpdateRewriteSettings(mock.Anything, adguard.RewriteSettings{
		Enabled: false,
	}).Return(nil).Once()

	rewrite := NewService(service)
	settings, err := rewrite.GetSettings(t.Context())

	require.NoError(t, err)
	assert.False(t, settings.Enabled)
	require.NoError(t, rewrite.UpdateSettings(t.Context(), Settings{Enabled: false}))
}

// TestServiceRejectsNilSettings verifies invalid successful responses are reported.
func TestServiceRejectsNilSettings(t *testing.T) {
	t.Parallel()

	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().GetRewriteSettings(mock.Anything).Return(nil, nil).Once()

	_, err := NewService(service).GetSettings(t.Context())

	require.ErrorIs(t, err, errNilSettings)
}

// TestServicePropagatesOperationErrors verifies public service failures remain matchable.
func TestServicePropagatesOperationErrors(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("rewrite unavailable")
	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().ListRewriteRules(mock.Anything).Return(nil, wantErr).Once()
	service.EXPECT().AddRewriteRule(mock.Anything, mock.Anything).Return(wantErr).Once()
	service.EXPECT().DeleteRewriteRule(mock.Anything, mock.Anything).Return(wantErr).Once()
	service.EXPECT().UpdateRewriteRule(mock.Anything, mock.Anything).Return(wantErr).Once()
	service.EXPECT().GetRewriteSettings(mock.Anything).Return(nil, wantErr).Once()
	service.EXPECT().UpdateRewriteSettings(mock.Anything, mock.Anything).Return(wantErr).Once()

	rewrite := NewService(service)
	_, listErr := rewrite.List(t.Context())
	addErr := rewrite.Add(t.Context(), RuleRequest{})
	deleteErr := rewrite.Delete(t.Context(), RuleRequest{})
	updateErr := rewrite.Update(t.Context(), RuleRequest{})
	_, settingsErr := rewrite.GetSettings(t.Context())
	updateSettingsErr := rewrite.UpdateSettings(t.Context(), Settings{})

	require.ErrorIs(t, listErr, wantErr)
	require.ErrorIs(t, addErr, wantErr)
	require.ErrorIs(t, deleteErr, wantErr)
	require.ErrorIs(t, updateErr, wantErr)
	require.ErrorIs(t, settingsErr, wantErr)
	require.ErrorIs(t, updateSettingsErr, wantErr)
}

// TestServicePreservesCancellation verifies cancellation reaches the public service.
func TestServicePreservesCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().ListRewriteRules(mock.Anything).RunAndReturn(
		func(ctx context.Context) ([]adguard.RewriteRule, error) {
			return nil, ctx.Err()
		},
	).Once()

	_, err := NewService(service).List(ctx)

	require.ErrorIs(t, err, context.Canceled)
}
