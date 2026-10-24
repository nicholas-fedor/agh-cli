// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"testing"

	"github.com/spf13/pflag"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// TestInstanceSelectionBindPublishesFlags verifies the published names,
// shorthands, defaults, and help of the selection flags.
func TestInstanceSelectionBindPublishesFlags(t *testing.T) {
	t.Parallel()

	fs := parsedFlags(t, new(InstanceSelection).Bind)

	assertFlag(t, fs, "all", "a", "false", "target all instances")
	assertFlag(t, fs, "instance", "i", "[]", "target instance name(s)")
}

// TestInstanceSelectionSelectionReadsFlags verifies that the parsed flags
// become the application selection.
func TestInstanceSelectionSelectionReadsFlags(t *testing.T) {
	t.Parallel()

	values := new(InstanceSelection)
	parsedFlags(t, values.Bind, "--all", "--instance", "alpha", "-i", "zulu")

	assert.Equal(t, app.Selection{Names: []string{"alpha", "zulu"}, All: true}, values.Selection())
}

// TestInstanceSelectionSelectionCopiesNames verifies that the selection owns its
// names, so a later change to the flag values cannot alter it.
func TestInstanceSelectionSelectionCopiesNames(t *testing.T) {
	t.Parallel()

	values := &InstanceSelection{Names: []string{"alpha"}, All: false}
	selection := values.Selection()

	values.Names[0] = "zulu"

	assert.Equal(t, []string{"alpha"}, selection.Names)
}

// parsedFlags binds a flag container to a fresh flag set and parses arguments.
//
// Parameters:
//   - bind: Bind method of the container under test.
//   - args: command-line arguments to parse.
//
// Returns:
//   - *pflag.FlagSet: the parsed flag set.
func parsedFlags(t *testing.T, bind func(*pflag.FlagSet), args ...string) *pflag.FlagSet {
	t.Helper()

	fs := pflag.NewFlagSet("test", pflag.ContinueOnError)
	bind(fs)
	require.NoError(t, fs.Parse(args))

	return fs
}

// assertFlag checks the published metadata of one flag.
//
// Parameters:
//   - fs: flag set that holds the flag.
//   - name: long flag name.
//   - shorthand: one-letter shorthand, or an empty string for none.
//   - def: rendered default value.
//   - usage: help text.
func assertFlag(t *testing.T, fs *pflag.FlagSet, name, shorthand, def, usage string) {
	t.Helper()

	flag := fs.Lookup(name)
	require.NotNil(t, flag, "flag %q", name)
	assert.Equal(t, shorthand, flag.Shorthand, "flag %q shorthand", name)
	assert.Equal(t, def, flag.DefValue, "flag %q default", name)
	assert.Equal(t, usage, flag.Usage, "flag %q usage", name)
}
