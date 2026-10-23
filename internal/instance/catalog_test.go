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

// TestNewCatalogRejectsConflictingIdentity verifies that two names that differ
// only by letter case cannot share a catalog.
func TestNewCatalogRejectsConflictingIdentity(t *testing.T) {
	t.Parallel()

	_, err := NewCatalog([]Config{
		catalogConfig("home", "first.example.com"),
		catalogConfig("Home", "second.example.com"),
	})

	require.ErrorIs(t, err, ErrConflictingInstance)
	require.ErrorContains(t, err, `"home" and "Home"`)
}

// TestNewCatalogRejectsInvalidInput verifies whole-catalog validation.
func TestNewCatalogRejectsInvalidInput(t *testing.T) {
	t.Parallel()

	_, err := NewCatalog([]Config{
		catalogConfig(alphaName, alphaTestHost),
		catalogConfig("invalid", ""),
	})

	require.ErrorIs(t, err, ErrMissingHost)
}

// TestNewCatalogEmptyCatalogFailsSelection verifies an empty catalog.
func TestNewCatalogEmptyCatalogFailsSelection(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog(nil)
	require.NoError(t, err)

	_, err = catalog.Select(nil, ExplicitOrDefaultSelection)

	require.ErrorIs(t, err, ErrEmptyCatalog)
}

// TestNewCatalogValidatesWithoutResolving verifies that a credential reference
// is normalized without contacting a credential source.
func TestNewCatalogValidatesWithoutResolving(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog([]Config{keyringInstance()})
	require.NoError(t, err)

	assert.Equal(t, &CredentialRef{Source: KeyringSource, Key: alphaName}, catalog.All()[0].Credential)
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

// TestCatalogResolveAppliesResolver verifies per-instance resolution in catalog
// order and context propagation.
func TestCatalogResolveAppliesResolver(t *testing.T) {
	t.Parallel()

	ctx := context.WithValue(t.Context(), resolverMarker{}, resolvedMarker)
	seen := make([]Config, 0, 2)

	resolve := resolverFunc(func(got context.Context, cfg Config) (Config, error) {
		assert.Equal(t, resolvedMarker, got.Value(resolverMarker{}))

		seen = append(seen, cfg)

		cfg.Password = resolvedPassword

		return cfg, nil
	})

	catalog, err := NewCatalog([]Config{keyringInstance(), catalogConfig(zuluName, zuluTestHost)})
	require.NoError(t, err)

	resolved, err := catalog.Resolve(ctx, resolve)
	require.NoError(t, err)

	all := resolved.All()
	assert.Equal(t, []ID{alphaName, zuluName}, configIdentities(all))
	assert.Equal(t, []ID{alphaName, zuluName}, configIdentities(seen))
	assert.Equal(t, defaultScheme, seen[0].Scheme)
	assert.Equal(t, resolvedPassword, all[0].Password)
	assert.Equal(t, resolvedPassword, all[1].Password)
	assert.Empty(t, catalog.All()[0].Password)
}

// TestCatalogResolveWithoutResolver verifies that a nil resolver leaves the
// catalog unresolved.
func TestCatalogResolveWithoutResolver(t *testing.T) {
	t.Parallel()

	catalog, err := NewCatalog([]Config{keyringInstance()})
	require.NoError(t, err)

	resolved, err := catalog.Resolve(t.Context(), nil)
	require.NoError(t, err)

	assert.Equal(t, catalog.All(), resolved.All())
	assert.Empty(t, resolved.All()[0].Password)
}

// TestCatalogResolvePropagatesResolverError verifies that resolution failures
// name the instance and preserve the sentinel error.
func TestCatalogResolvePropagatesResolverError(t *testing.T) {
	t.Parallel()

	resolve := resolverFunc(func(_ context.Context, cfg Config) (Config, error) {
		return Config{}, fmt.Errorf("read key %q: %w", cfg.Credential.Key, errCredentialStore)
	})

	catalog, err := NewCatalog([]Config{keyringInstance()})
	require.NoError(t, err)

	_, err = catalog.Resolve(t.Context(), resolve)

	require.ErrorIs(t, err, errCredentialStore)
	assert.ErrorContains(t, err, alphaName)
}

// TestCatalogResolveRevalidatesResolverOutput verifies that a resolver cannot
// smuggle an invalid configuration into the catalog.
func TestCatalogResolveRevalidatesResolverOutput(t *testing.T) {
	t.Parallel()

	resolve := resolverFunc(func(_ context.Context, cfg Config) (Config, error) {
		cfg.Host = ""

		return cfg, nil
	})

	catalog, err := NewCatalog([]Config{catalogConfig(alphaName, alphaTestHost)})
	require.NoError(t, err)

	_, err = catalog.Resolve(t.Context(), resolve)

	require.ErrorIs(t, err, ErrMissingHost)
}

// catalogConfig returns an unvalidated instance without credentials.
//
// Parameters:
//   - name: instance name.
//   - host: instance host, or an empty string to omit it.
//
// Returns:
//   - Config: unvalidated instance configuration.
func catalogConfig(name, host string) Config {
	return Config{
		Name:       name,
		Host:       host,
		Scheme:     "",
		Username:   "",
		Password:   "",
		Credential: nil,
	}
}

// keyringInstance returns an unvalidated alpha instance that stores its
// password under the default keyring key.
//
// Returns:
//   - Config: unvalidated instance configuration.
func keyringInstance() Config {
	cfg := catalogConfig(alphaName, alphaTestHost)

	cfg.Credential = &CredentialRef{Source: KeyringSource}

	return cfg
}
