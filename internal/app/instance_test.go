// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

const (
	// InstanceTestDefaultName identifies the default instance-listing test target.
	instanceTestDefaultName = "default"
	// InstanceTestAlphaHost identifies the alpha instance-listing test host.
	instanceTestAlphaHost = "instance-alpha.example.com"
	// InstanceTestDefaultHost identifies the default instance-listing test host.
	instanceTestDefaultHost = "instance-default.example.com"
	// InstanceTestZuluHost identifies the zulu instance-listing test host.
	instanceTestZuluHost = "instance-zulu.example.com"
)

// TestListInstancesPreservesSelectionOrder verifies application-level resolution order.
func TestListInstancesPreservesSelectionOrder(t *testing.T) {
	t.Parallel()

	configs, err := ListInstances(InstanceListRequest{
		Instances: instance.Source{
			zuluInstance:            map[string]any{testHostKey: instanceTestZuluHost},
			instanceTestDefaultName: map[string]any{testHostKey: instanceTestDefaultHost},
			alphaInstance:           map[string]any{testHostKey: instanceTestAlphaHost},
		},
		All: true,
	})

	require.NoError(t, err)
	assert.Equal(
		t,
		[]instance.ID{alphaInstance, instanceTestDefaultName, zuluInstance},
		instanceConfigIdentities(configs),
	)
}

// TestListInstancesUsesDefault verifies implicit selection semantics.
func TestListInstancesUsesDefault(t *testing.T) {
	t.Parallel()

	configs, err := ListInstances(InstanceListRequest{
		Instances: instance.Source{
			zuluInstance:            map[string]any{testHostKey: instanceTestZuluHost},
			instanceTestDefaultName: map[string]any{testHostKey: instanceTestDefaultHost},
		},
		All: false,
	})

	require.NoError(t, err)
	assert.Equal(t, []instance.ID{instanceTestDefaultName}, instanceConfigIdentities(configs))
}

// TestListInstancesPreservesResolutionErrors verifies error causes survive app wrapping.
func TestListInstancesPreservesResolutionErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		request InstanceListRequest
		wantErr error
	}{
		{
			name: "empty source",
			request: InstanceListRequest{
				Instances: instance.Source{},
				All:       false,
			},
			wantErr: instance.ErrEmptyCatalog,
		},
		{
			name: "ambiguous implicit selection",
			request: InstanceListRequest{
				Instances: instance.Source{
					alphaInstance: map[string]any{testHostKey: instanceTestAlphaHost},
					zuluInstance:  map[string]any{testHostKey: instanceTestZuluHost},
				},
				All: false,
			},
			wantErr: instance.ErrTargetSelection,
		},
		{
			name: "invalid catalog entry",
			request: InstanceListRequest{
				Instances: instance.Source{
					instanceTestDefaultName: map[string]any{"scheme": "https"},
				},
				All: false,
			},
			wantErr: instance.ErrMissingHost,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			_, err := ListInstances(test.request)

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

// TestInstanceSourceReadsViper verifies that the configured instances are read as
// a typed source and fed to the catalog.
func TestInstanceSourceReadsViper(t *testing.T) {
	t.Parallel()

	lockViper(t)

	viper.Set(viperInstancesKey, map[string]any{
		instanceTestDefaultName: map[string]any{testHostKey: instanceTestDefaultHost},
		alphaInstance:           map[string]any{testHostKey: instanceTestAlphaHost},
	})

	instances, err := InstanceSource()

	require.NoError(t, err)
	assert.Equal(t, instance.Source{
		instanceTestDefaultName: map[string]any{testHostKey: instanceTestDefaultHost},
		alphaInstance:           map[string]any{testHostKey: instanceTestAlphaHost},
	}, instances)

	configs, err := ListInstances(InstanceListRequest{Instances: instances, All: true})

	require.NoError(t, err)
	assert.Equal(
		t,
		[]instance.ID{alphaInstance, instanceTestDefaultName},
		instanceConfigIdentities(configs),
	)
}

// TestInstanceSourceDefaultsToEmptySource verifies that a configuration without
// instances converts to an empty source instead of failing the read.
func TestInstanceSourceDefaultsToEmptySource(t *testing.T) {
	t.Parallel()

	lockViper(t)

	instances, err := InstanceSource()

	require.NoError(t, err)
	assert.Empty(t, instances)
}

// TestInstanceSourceRejectsInvalidConfiguration verifies that a mistyped
// configuration is reported by the read, so a command never selects an instance
// from an untyped value.
func TestInstanceSourceRejectsInvalidConfiguration(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		give    any
		wantErr error
	}{
		{
			name:    "non-map instances value",
			give:    "not-a-map",
			wantErr: instance.ErrNoConfigInstances,
		},
		{
			name: "non-map instance value",
			give: map[string]any{
				instanceTestDefaultName: "not-a-map",
			},
			wantErr: instance.ErrInvalidConfig,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			lockViper(t)

			viper.Set(viperInstancesKey, test.give)

			instances, err := InstanceSource()

			require.ErrorIs(t, err, test.wantErr)
			require.ErrorContains(t, err, viperInstancesKey)
			assert.Nil(t, instances)
		})
	}
}

// instanceConfigIdentities returns configuration identities in selection order.
//
// Parameters:
//   - configs: resolved instance configurations.
//
// Returns:
//   - []instance.ID: identities in selection order.
func instanceConfigIdentities(configs []instance.Config) []instance.ID {
	identities := make([]instance.ID, 0, len(configs))
	for _, cfg := range configs {
		identities = append(identities, cfg.Identity())
	}

	return identities
}
