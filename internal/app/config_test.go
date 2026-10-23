// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"io"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/config"
)

// windowsOS is the value [runtime.GOOS] reports for Microsoft Windows, where
// [os.UserConfigDir] reads the roaming application data directory.
const windowsOS = "windows"

// TestLoadRunConfigReadsResolvedFile verifies the run configuration serves the
// instances and the credential namespace of the file it loaded, with instance
// names exactly as the file writes them.
func TestLoadRunConfigReadsResolvedFile(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t,
		"credentials:\n  service: agh-cli-custom\n"+
			"instances:\n  Home:\n    host: "+testConfigHost+"\n",
	)

	resolution, err := ResolveConfigPath(configPath)
	require.NoError(t, err)

	var warnings strings.Builder

	runConfig, err := LoadRunConfig(resolution, &warnings)
	require.NoError(t, err)

	ctx := WithRunConfig(t.Context(), runConfig)

	manager, err := configFrom(ctx)
	require.NoError(t, err)
	assert.Equal(t, []string{"Home"}, manager.OrderedNames())
	assert.Equal(t, "agh-cli-custom", credentialService(ctx))
	assert.Empty(t, warnings.String())
}

// TestLoadRunConfigWarnsAboutMissingFile verifies a missing file loads as an
// empty configuration and is reported as a warning naming the file.
func TestLoadRunConfigWarnsAboutMissingFile(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), config.DefaultConfigFileName)

	var warnings strings.Builder

	runConfig, err := LoadRunConfig(config.Resolution{Path: configPath, Exists: false}, &warnings)
	require.NoError(t, err)

	manager, err := configFrom(WithRunConfig(t.Context(), runConfig))
	require.NoError(t, err)
	assert.Empty(t, manager.OrderedNames())
	assert.Contains(t, warnings.String(), "no configuration file at "+configPath)
}

// TestLoadRunConfigWarnsAboutInstanceProblems verifies a problem with one
// instance is a warning naming it, never a load failure, so the instance can
// still be removed.
func TestLoadRunConfigWarnsAboutInstanceProblems(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t, "instances:\n  broken: https\n  hostless:\n    Host: x\n")

	var warnings strings.Builder

	_, err := LoadRunConfig(config.Resolution{Path: configPath, Exists: true}, &warnings)

	require.NoError(t, err)
	assert.Contains(t, warnings.String(), configPath)
	assert.Contains(t, warnings.String(), "broken: ")
	assert.Contains(t, warnings.String(), "hostless: unknown field")
}

// TestLoadRunConfigNamesUnreadableFile verifies a file that cannot be parsed is
// reported with its path, because an operator must know which file failed.
func TestLoadRunConfigNamesUnreadableFile(t *testing.T) {
	t.Parallel()

	configPath := writeTestConfig(t, "instances: [\n")

	_, err := LoadRunConfig(config.Resolution{Path: configPath, Exists: true}, io.Discard)

	require.Error(t, err)
	assert.Contains(t, err.Error(), strconv.Quote(configPath))
}

// TestLoadRunConfigRefusesUnsupportedFormat verifies a path naming another
// format is refused, so a write never puts YAML into it.
func TestLoadRunConfigRefusesUnsupportedFormat(t *testing.T) {
	t.Parallel()

	configPath := filepath.Join(t.TempDir(), "config.toml")

	_, err := LoadRunConfig(config.Resolution{Path: configPath, Exists: false}, io.Discard)

	require.ErrorIs(t, err, config.ErrUnsupportedFormat)
	assert.Contains(t, err.Error(), strconv.Quote(configPath))
}

// TestConfigFromRequiresRunConfig verifies a context without a loaded
// configuration is reported rather than read as an empty configuration.
func TestConfigFromRequiresRunConfig(t *testing.T) {
	t.Parallel()

	_, err := configFrom(t.Context())

	require.ErrorIs(t, err, ErrNoRunConfig)
}
