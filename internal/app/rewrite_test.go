// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
	mockAdguard "github.com/nicholas-fedor/agh-cli/pkg/adguard/mocks"
)

const (
	// RewriteTestDomain is the rewritten domain used in rewrite tests.
	rewriteTestDomain = "example.com"
	// RewriteTestAnswer is the rewritten answer used in rewrite tests.
	rewriteTestAnswer = "192.0.2.1"
)

// TestRewriteManagementListContinuesAfterFailure verifies partial list results survive failures.
func TestRewriteManagementListContinuesAfterFailure(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("list unavailable")
	badService := mockAdguard.NewMockRewriteService(t)
	badService.EXPECT().ListRewriteRules(mock.Anything).Return(nil, wantErr).Once()

	goodService := mockAdguard.NewMockRewriteService(t)
	goodService.EXPECT().ListRewriteRules(mock.Anything).Return([]adguard.RewriteRule{{
		Domain:  new(rewriteTestDomain),
		Answer:  new(rewriteTestAnswer),
		Enabled: new(false),
	}}, nil).Once()

	results, err := testRewriteManagement(t, map[string]*mockAdguard.MockRewriteService{
		badInstance:  badService,
		goodInstance: goodService,
	}).List(t.Context(), RewriteSelection{
		Instances: testInstances(),
		Names:     []string{badInstance, goodInstance},
	})

	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, []RewriteListResult{{
		Instance: goodInstance,
		Rules: []RewriteRule{{
			Domain:  rewriteTestDomain,
			Answer:  rewriteTestAnswer,
			Enabled: false,
		}},
		Index:         1,
		InstanceCount: 2,
	}}, results)
}

// TestRewriteManagementListUsesConfigurationOrder verifies read and result ordering.
func TestRewriteManagementListUsesConfigurationOrder(t *testing.T) {
	t.Parallel()

	var mutex sync.Mutex

	calls := make([]string, 0, 2)
	management := &RewriteManagement{newService: func(cfg instance.Config) (adguard.RewriteService, error) {
		service := mockAdguard.NewMockRewriteService(t)
		service.EXPECT().ListRewriteRules(mock.Anything).RunAndReturn(
			func(context.Context) ([]adguard.RewriteRule, error) {
				mutex.Lock()

				calls = append(calls, cfg.Name)
				mutex.Unlock()

				return []adguard.RewriteRule{}, nil
			},
		).Once()

		return service, nil
	}}

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configData := fmt.Appendf(
		nil,
		"instances:\n  %s:\n    host: %s\n  %s:\n    host: %s\n",
		zuluInstance,
		testZuluHost,
		alphaInstance,
		testAlphaHost,
	)
	require.NoError(t, os.WriteFile(configPath, configData, 0o600))

	results, err := management.List(t.Context(), RewriteSelection{
		Instances: instance.Source{
			alphaInstance: map[string]any{testHostKey: testAlphaHost},
			zuluInstance:  map[string]any{testHostKey: testZuluHost},
		},
		All:        true,
		ConfigPath: configPath,
	})

	require.NoError(t, err)
	assert.Equal(t, []RewriteListResult{
		{Instance: zuluInstance, Rules: []RewriteRule{}, Index: 0, InstanceCount: 2},
		{Instance: alphaInstance, Rules: []RewriteRule{}, Index: 1, InstanceCount: 2},
	}, results)
	assert.Equal(t, []string{zuluInstance, alphaInstance}, calls)
}

// TestRewriteManagementMutationUsesExplicitOrderAndReturnsPartialResults verifies target behavior.
func TestRewriteManagementMutationUsesExplicitOrderAndReturnsPartialResults(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("add unavailable")
	zuluService := mockAdguard.NewMockRewriteService(t)
	zuluService.EXPECT().AddRewriteRule(mock.Anything, adguard.RewriteRule{
		Domain:  new(rewriteTestDomain),
		Answer:  new(rewriteTestAnswer),
		Enabled: new(false),
	}).Return(nil).Once()

	alphaService := mockAdguard.NewMockRewriteService(t)
	alphaService.EXPECT().AddRewriteRule(mock.Anything, mock.Anything).Return(wantErr).Once()

	results, err := testRewriteManagement(t, map[string]*mockAdguard.MockRewriteService{
		zuluInstance:  zuluService,
		alphaInstance: alphaService,
	}).Add(t.Context(), RewriteSelection{
		Instances: testInstances(),
		Names:     []string{zuluInstance, alphaInstance, zuluInstance},
	}, RewriteRuleInput{
		Domain:  rewriteTestDomain,
		Answer:  rewriteTestAnswer,
		Enabled: false,
	})

	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, []RewriteMutationResult{{
		Instance: zuluInstance,
		Message:  "Added rewrite rule example.com -> 192.0.2.1",
	}}, results)
}

// TestRewriteManagementUpdatePreservesFalseAndZeroTarget verifies app-to-domain request shaping.
func TestRewriteManagementUpdatePreservesFalseAndZeroTarget(t *testing.T) {
	t.Parallel()

	rule := adguard.RewriteRule{
		Domain:  new(rewriteTestDomain),
		Answer:  new(rewriteTestAnswer),
		Enabled: new(false),
	}
	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().UpdateRewriteRule(mock.Anything, adguard.RewriteUpdate{Update: rule}).Return(nil).Once()

	results, err := testRewriteManagement(t, map[string]*mockAdguard.MockRewriteService{
		goodInstance: service,
	}).Update(t.Context(), RewriteSelection{
		Instances: testInstances(),
		Names:     []string{goodInstance},
	}, RewriteRuleInput{
		Domain:  rewriteTestDomain,
		Answer:  rewriteTestAnswer,
		Enabled: false,
	})

	require.NoError(t, err)
	assert.Equal(t, []RewriteMutationResult{{
		Instance: goodInstance,
		Message:  "Updated rewrite rule example.com -> 192.0.2.1",
	}}, results)
}

// TestRewriteManagementSettingsPreserveFalseAndPartialResults verifies settings behavior.
func TestRewriteManagementSettingsPreserveFalseAndPartialResults(t *testing.T) {
	t.Parallel()

	wantErr := errors.New("settings unavailable")
	badService := mockAdguard.NewMockRewriteService(t)
	badService.EXPECT().GetRewriteSettings(mock.Anything).Return(nil, wantErr).Once()

	goodService := mockAdguard.NewMockRewriteService(t)
	goodService.EXPECT().GetRewriteSettings(mock.Anything).Return(&adguard.RewriteSettings{
		Enabled: false,
	}, nil).Once()
	goodService.EXPECT().UpdateRewriteSettings(mock.Anything, adguard.RewriteSettings{
		Enabled: false,
	}).Return(nil).Once()

	management := testRewriteManagement(t, map[string]*mockAdguard.MockRewriteService{
		badInstance:  badService,
		goodInstance: goodService,
	})
	selection := RewriteSelection{
		Instances: testInstances(),
		Names:     []string{badInstance, goodInstance},
	}

	results, err := management.GetSettings(t.Context(), selection)

	require.ErrorIs(t, err, wantErr)
	assert.Equal(t, []RewriteSettingsResult{{
		Instance:      goodInstance,
		Enabled:       false,
		Index:         1,
		InstanceCount: 2,
	}}, results)

	updateResults, err := management.UpdateSettings(t.Context(), RewriteSelection{
		Instances: testInstances(),
		Names:     []string{goodInstance},
	}, false)

	require.NoError(t, err)
	assert.Equal(t, []RewriteMutationResult{{
		Instance: goodInstance,
		Message:  "Rewrite settings updated: enabled=false",
	}}, updateResults)
}

// TestRewriteManagementCancellationStopsRemainingTargets verifies cancellation prevents later calls.
func TestRewriteManagementCancellationStopsRemainingTargets(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().ListRewriteRules(mock.Anything).RunAndReturn(
		func(context.Context) ([]adguard.RewriteRule, error) {
			cancel()

			return nil, context.Canceled
		},
	).Once()

	factoryCalls := 0
	management := &RewriteManagement{newService: func(_ instance.Config) (adguard.RewriteService, error) {
		factoryCalls++

		return service, nil
	}}

	results, err := management.List(ctx, RewriteSelection{
		Instances: testInstances(),
		All:       true,
	})

	require.ErrorIs(t, err, context.Canceled)
	assert.Empty(t, results)
	assert.Equal(t, 1, factoryCalls)
}

// TestRewriteManagementDiffFilePreservesBaselineSemantics verifies file parsing and comparison order.
func TestRewriteManagementDiffFilePreservesBaselineSemantics(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "rules.yaml")
	contents := []byte("- domain: local.example\n  answer: 192.0.2.2\n  enabled: true\n")
	require.NoError(t, os.WriteFile(path, contents, 0o600))

	service := mockAdguard.NewMockRewriteService(t)
	service.EXPECT().ListRewriteRules(mock.Anything).Return([]adguard.RewriteRule{{
		Domain:  new("remote.example"),
		Answer:  new(rewriteTestAnswer),
		Enabled: new(false),
	}}, nil).Once()

	result, err := testRewriteManagement(t, map[string]*mockAdguard.MockRewriteService{
		goodInstance: service,
	}).Diff(t.Context(), RewriteSelection{
		Instances: testInstances(),
		Names:     []string{goodInstance},
	}, path)

	require.NoError(t, err)
	assert.Equal(t, RewriteDiffFile, result.Mode)
	assert.Equal(t, []string{goodInstance}, result.InstanceNames)
	require.Len(t, result.Diff.Added, 1)
	assert.Equal(t, "remote.example", result.Diff.Added[0].Domain)
	require.Len(t, result.Diff.Removed, 1)
	assert.Equal(t, "local.example", result.Diff.Removed[0].Domain)
}

// TestRewriteManagementDiffInstancesUsesSortedNames verifies comparison target ordering.
func TestRewriteManagementDiffInstancesUsesSortedNames(t *testing.T) {
	t.Parallel()

	var mutex sync.Mutex

	calls := make([]string, 0, 2)
	management := &RewriteManagement{newService: func(cfg instance.Config) (adguard.RewriteService, error) {
		mutex.Lock()

		calls = append(calls, cfg.Name)
		mutex.Unlock()

		service := mockAdguard.NewMockRewriteService(t)
		service.EXPECT().ListRewriteRules(mock.Anything).Return(nil, nil).Once()

		return service, nil
	}}

	result, err := management.Diff(t.Context(), RewriteSelection{
		Instances: testInstances(),
		Names:     []string{zuluInstance, alphaInstance},
	}, "")

	require.NoError(t, err)
	assert.Equal(t, RewriteDiffInstances, result.Mode)
	assert.Equal(t, []string{alphaInstance, zuluInstance}, result.InstanceNames)
	assert.Equal(t, []string{alphaInstance, zuluInstance}, calls)
}

// testRewriteManagement creates app wiring backed by generated rewrite mocks.
//
// Parameters:
//   - services: mock services keyed by instance name.
//
// Returns:
//   - *RewriteManagement: management resolving one mock per instance name.
func testRewriteManagement(
	t *testing.T,
	services map[string]*mockAdguard.MockRewriteService,
) *RewriteManagement {
	t.Helper()

	return &RewriteManagement{newService: func(cfg instance.Config) (adguard.RewriteService, error) {
		service, exists := services[cfg.Name]
		if !exists {
			return nil, fmt.Errorf("unexpected instance %q", cfg.Name)
		}

		return service, nil
	}}
}
