// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resolverMarker is the context key carrying the value resolver stubs require.
type resolverMarker struct{}

// resolverFunc adapts a function to CredentialResolver.
type resolverFunc func(context.Context, Config) (Config, error)

const (
	// AlphaName identifies the alpha test instance.
	alphaName = "alpha"
	// ZuluName identifies the zulu test instance.
	zuluName = "zulu"
	// AlphaTestHost is the alpha test host.
	alphaTestHost = "alpha.example.com"
	// ZuluTestHost is the zulu test host.
	zuluTestHost = "zulu.example.com"
	// HostKey is the raw instance host key.
	hostKey = "host"
	// ResolvedMarker is the context value the resolver stub requires.
	resolvedMarker = "resolved-marker"
	// ResolvedPassword is the password the resolver stub returns.
	resolvedPassword = "resolved-secret"
)

// errCredentialStore is the sentinel failure returned by resolver stubs.
var errCredentialStore = errors.New("credential store unavailable")

// Resolve applies the stubbed credential resolution.
//
// Parameters:
//   - ctx: context forwarded by catalog construction.
//   - cfg: validated configuration under resolution.
//
// Returns:
//   - Config: the configuration produced by the stub function.
//   - error: the error produced by the stub function.
func (resolve resolverFunc) Resolve(ctx context.Context, cfg Config) (Config, error) {
	return resolve(ctx, cfg)
}

// TestCatalogSelect verifies ordered target-selection policy.
func TestCatalogSelect(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog([]Config{
		{
			Name: zuluName, Host: zuluTestHost, Scheme: defaultScheme,
			Username: "", Password: "", Credential: nil,
		},
		{
			Name: defaultInstanceName, Host: "home.example.com", Scheme: defaultScheme,
			Username: "", Password: "", Credential: nil,
		},
		{
			Name: alphaName, Host: alphaTestHost, Scheme: defaultScheme,
			Username: "", Password: "", Credential: nil,
		},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		give    []string
		mode    SelectionMode
		wantIDs []ID
		wantErr error
	}{
		{
			name:    "all preserves catalog order",
			give:    nil,
			mode:    AllSelection,
			wantIDs: []ID{zuluName, defaultInstanceName, alphaName},
			wantErr: nil,
		},
		{
			name:    "explicit preserves first CLI occurrence",
			give:    []string{alphaName, zuluName, alphaName},
			mode:    ExplicitOrDefaultSelection,
			wantIDs: []ID{alphaName, zuluName},
			wantErr: nil,
		},
		{
			name:    "default fallback",
			give:    nil,
			mode:    ExplicitOrDefaultSelection,
			wantIDs: []ID{defaultInstanceName},
			wantErr: nil,
		},
		{
			name:    "unknown explicit target",
			give:    []string{"missing"},
			mode:    ExplicitOrDefaultSelection,
			wantIDs: nil,
			wantErr: ErrUnknownInstance,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			selected, err := catalog.Select(test.give, test.mode)
			if test.wantErr != nil {
				require.ErrorIs(t, err, test.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, test.wantIDs, configIdentities(selected))
		})
	}
}

// TestCatalogSelectRejectsInvalidMode verifies explicit mode validation.
func TestCatalogSelectRejectsInvalidMode(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog([]Config{{
		Name: alphaName, Host: alphaTestHost, Scheme: defaultScheme,
		Username: "", Password: "", Credential: nil,
	}})
	require.NoError(t, err)

	_, err = catalog.Select(nil, SelectionMode(255))

	require.ErrorIs(t, err, ErrInvalidSelection)
}

// TestCatalogSelectRejectsAmbiguousImplicitSelection verifies fallback errors.
func TestCatalogSelectRejectsAmbiguousImplicitSelection(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog([]Config{
		{
			Name: alphaName, Host: alphaTestHost, Scheme: defaultScheme,
			Username: "", Password: "", Credential: nil,
		},
		{
			Name: zuluName, Host: zuluTestHost, Scheme: defaultScheme,
			Username: "", Password: "", Credential: nil,
		},
	})
	require.NoError(t, err)

	_, err = catalog.Select(nil, ExplicitOrDefaultSelection)

	require.ErrorIs(t, err, ErrTargetSelection)
}

// TestCatalogSelectSingleInstanceFallback verifies implicit singleton selection.
func TestCatalogSelectSingleInstanceFallback(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog([]Config{{
		Name: "only", Host: "only.example.com", Scheme: defaultScheme,
		Username: "", Password: "", Credential: nil,
	}})
	require.NoError(t, err)

	selected, err := catalog.Select(nil, ExplicitOrDefaultSelection)

	require.NoError(t, err)
	assert.Equal(t, []ID{"only"}, configIdentities(selected))
}

// TestNewCatalogRejectsDuplicateIdentity verifies catalog uniqueness.
func TestNewCatalogRejectsDuplicateIdentity(t *testing.T) {
	t.Parallel()

	_, err := NewCatalog([]Config{
		{
			Name: "duplicate", Host: "first.example.com", Scheme: defaultScheme,
			Username: "", Password: "", Credential: nil,
		},
		{
			Name: "duplicate", Host: "second.example.com", Scheme: defaultScheme,
			Username: "", Password: "", Credential: nil,
		},
	})

	require.ErrorIs(t, err, ErrDuplicateInstance)
}

// TestCatalogAllReturnsSnapshot verifies copy isolation.
func TestCatalogAllReturnsSnapshot(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog([]Config{{
		Name: "home", Host: "home.example.com", Scheme: defaultScheme,
		Username: "", Password: "", Credential: nil,
	}})
	require.NoError(t, err)

	give := catalog.All()

	give[0].Host = "changed.example.com"

	all := catalog.All()
	assert.Equal(t, "home.example.com", all[0].Host)
}

// TestSourceFromValueConvertsConfiguredMapping verifies that a configured
// mapping becomes a typed source and that an absent or empty mapping converts to
// an empty source.
func TestSourceFromValueConvertsConfiguredMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		give any
		want Source
	}{
		{
			name: "configured instances",
			give: map[string]any{
				zuluName:  map[string]any{hostKey: zuluTestHost},
				alphaName: map[string]any{hostKey: alphaTestHost},
			},
			want: Source{
				zuluName:  map[string]any{hostKey: zuluTestHost},
				alphaName: map[string]any{hostKey: alphaTestHost},
			},
		},
		{
			name: "absent mapping",
			give: nil,
			want: Source{},
		},
		{
			name: "empty mapping",
			give: map[string]any{},
			want: Source{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			source, err := SourceFromValue(test.give)

			require.NoError(t, err)
			assert.Equal(t, test.want, source)
		})
	}
}

// TestSourceFromValueRejectsInvalidMapping verifies that a mistyped mapping is
// reported instead of being skipped, so a bad instance never falls back to
// another instance.
func TestSourceFromValueRejectsInvalidMapping(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		give    any
		wantErr error
	}{
		{
			name:    "non-map instances value",
			give:    "not-a-map",
			wantErr: ErrNoConfigInstances,
		},
		{
			name: "non-map instance value",
			give: map[string]any{
				alphaName: "not-a-map",
			},
			wantErr: ErrInvalidConfig,
		},
		{
			name: "nil instance value",
			give: map[string]any{
				alphaName: nil,
			},
			wantErr: ErrInvalidConfig,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			source, err := SourceFromValue(test.give)

			require.ErrorIs(t, err, test.wantErr)
			assert.Nil(t, source)
		})
	}
}

// TestCatalogFromSourceSelection verifies source conversion and selection.
func TestCatalogFromSourceSelection(t *testing.T) {
	t.Parallel()

	catalog, err := CatalogFromSource(Source{
		zuluName:            map[string]any{hostKey: zuluTestHost},
		defaultInstanceName: map[string]any{hostKey: "default.example.com"},
		alphaName:           map[string]any{hostKey: alphaTestHost},
	})
	require.NoError(t, err)

	tests := []struct {
		name    string
		give    []string
		mode    SelectionMode
		wantIDs []ID
		wantErr error
	}{
		{
			name:    "all takes precedence and preserves sorted catalog order",
			give:    []string{"unknown"},
			mode:    AllSelection,
			wantIDs: []ID{alphaName, defaultInstanceName, zuluName},
			wantErr: nil,
		},
		{
			name:    "explicit preserves first occurrence",
			give:    []string{zuluName, alphaName, zuluName},
			mode:    ExplicitOrDefaultSelection,
			wantIDs: []ID{zuluName, alphaName},
			wantErr: nil,
		},
		{
			name:    "default fallback",
			give:    nil,
			mode:    ExplicitOrDefaultSelection,
			wantIDs: []ID{defaultInstanceName},
			wantErr: nil,
		},
		{
			name:    "unknown explicit target",
			give:    []string{"unknown"},
			mode:    ExplicitOrDefaultSelection,
			wantIDs: nil,
			wantErr: ErrUnknownInstance,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			selected, selectErr := catalog.Select(test.give, test.mode)
			if test.wantErr != nil {
				require.ErrorIs(t, selectErr, test.wantErr)

				return
			}

			require.NoError(t, selectErr)
			assert.Equal(t, test.wantIDs, configIdentities(selected))
		})
	}
}

// TestCatalogFromSourceRejectsInvalidInput verifies whole-catalog validation.
func TestCatalogFromSourceRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	_, err := CatalogFromSource(Source{
		alphaName: map[string]any{hostKey: alphaTestHost},
		"invalid": map[string]any{"scheme": defaultScheme},
	})

	require.ErrorIs(t, err, ErrMissingHost)
}

// TestCatalogFromSourceEmptyCatalogFailsSelection verifies an empty source.
func TestCatalogFromSourceEmptyCatalogFailsSelection(t *testing.T) {
	t.Parallel()

	catalog, err := CatalogFromSource(Source{})
	require.NoError(t, err)

	_, err = catalog.Select(nil, ExplicitOrDefaultSelection)

	require.ErrorIs(t, err, ErrEmptyCatalog)
}

// configIdentities returns configuration identities in slice order.
//
// Parameters:
//   - configs: configurations whose identities are requested.
//
// Returns:
//   - []ID: identities in the same order as configs.
func configIdentities(configs []Config) []ID {
	ids := make([]ID, 0, len(configs))
	for _, cfg := range configs {
		ids = append(ids, cfg.Identity())
	}

	return ids
}

// TestCatalogFromSourceResolvedAppliesResolver verifies per-instance resolution in
// catalog order and context propagation.
func TestCatalogFromSourceResolvedAppliesResolver(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), resolverMarker{}, resolvedMarker)
	seen := make([]Config, 0, 2)

	resolve := resolverFunc(func(got context.Context, cfg Config) (Config, error) {
		assert.Equal(t, resolvedMarker, got.Value(resolverMarker{}))

		seen = append(seen, cfg)

		cfg.Password = resolvedPassword

		return cfg, nil
	})

	catalog, err := CatalogFromSourceResolved(ctx, Source{
		zuluName:  map[string]any{hostKey: zuluTestHost},
		alphaName: keyringInstance(),
	}, resolve)
	require.NoError(t, err)

	all := catalog.All()
	assert.Equal(t, []ID{alphaName, zuluName}, configIdentities(all))
	assert.Equal(t, []ID{alphaName, zuluName}, configIdentities(seen))
	assert.Equal(t, defaultScheme, seen[0].Scheme)
	assert.Equal(t, resolvedPassword, all[0].Password)
	assert.Equal(t, resolvedPassword, all[1].Password)
}

// TestCatalogFromSourceResolvedWithoutResolver verifies that a nil resolver matches
// the unresolved CatalogFromSource behavior.
func TestCatalogFromSourceResolvedWithoutResolver(t *testing.T) {
	t.Parallel()

	give := Source{alphaName: keyringInstance()}

	catalog, err := CatalogFromSourceResolved(t.Context(), give, nil)
	require.NoError(t, err)

	unresolved, err := CatalogFromSource(give)
	require.NoError(t, err)
	assert.Equal(t, unresolved.All(), catalog.All())
	assert.Empty(t, catalog.All()[0].Password)
}

// TestCatalogFromSourceValidatesWithoutResolving verifies that CatalogFromSource
// normalizes a credential reference without contacting a credential source.
func TestCatalogFromSourceValidatesWithoutResolving(t *testing.T) {
	t.Parallel()

	catalog, err := CatalogFromSource(Source{alphaName: keyringInstance()})
	require.NoError(t, err)

	assert.Equal(t, &CredentialRef{Source: KeyringSource, Key: alphaName}, catalog.All()[0].Credential)
}

// TestCatalogFromSourceResolvedPropagatesResolverError verifies that resolution
// failures name the instance and preserve the sentinel error.
func TestCatalogFromSourceResolvedPropagatesResolverError(t *testing.T) {
	t.Parallel()

	resolve := resolverFunc(func(_ context.Context, cfg Config) (Config, error) {
		return Config{}, fmt.Errorf("read key %q: %w", cfg.Credential.Key, errCredentialStore)
	})

	_, err := CatalogFromSourceResolved(t.Context(), Source{
		alphaName: keyringInstance(),
	}, resolve)

	require.ErrorIs(t, err, errCredentialStore)
	assert.ErrorContains(t, err, alphaName)
}

// TestCatalogFromSourceResolvedRejectsInvalidCredential verifies that
// configuration validation precedes credential resolution.
func TestCatalogFromSourceResolvedRejectsInvalidCredential(t *testing.T) {
	t.Parallel()

	calls := 0

	resolve := resolverFunc(func(_ context.Context, cfg Config) (Config, error) {
		calls++

		return cfg, nil
	})

	_, err := CatalogFromSourceResolved(t.Context(), Source{
		alphaName: map[string]any{
			hostKey: alphaTestHost,
			credentialFieldName: map[string]any{
				sourceFieldName: unknownSource,
			},
		},
	}, resolve)

	require.ErrorIs(t, err, ErrInvalidCredentialSource)
	assert.Zero(t, calls)
}

// TestCatalogFromSourceResolvedRevalidatesResolverOutput verifies that a resolver
// cannot smuggle an invalid configuration into the catalog.
func TestCatalogFromSourceResolvedRevalidatesResolverOutput(t *testing.T) {
	t.Parallel()

	resolve := resolverFunc(func(_ context.Context, cfg Config) (Config, error) {
		cfg.Host = ""

		return cfg, nil
	})

	_, err := CatalogFromSourceResolved(t.Context(), Source{
		alphaName: map[string]any{hostKey: alphaTestHost},
	}, resolve)

	require.ErrorIs(t, err, ErrMissingHost)
}

// keyringInstance returns a raw instance mapping that stores its password under
// the default keyring key.
//
// Returns:
//   - map[string]any: raw instance mapping.
func keyringInstance() map[string]any {
	return map[string]any{
		hostKey: alphaTestHost,
		credentialFieldName: map[string]any{
			sourceFieldName: string(KeyringSource),
		},
	}
}
