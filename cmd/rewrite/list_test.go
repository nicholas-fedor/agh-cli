// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app/apptest"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// TestListReturnsInstanceFailure verifies that rewrite list fails when an instance request fails.
func TestListReturnsInstanceFailure(t *testing.T) {
	t.Parallel()

	server := httptest.NewTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	server.Start()

	configPath := filepath.Join(t.TempDir(), "config.yaml")
	configData := fmt.Appendf(
		nil,
		"instances:\n  test:\n    host: %q\n    scheme: http\n",
		server.Listener.Addr().String(),
	)
	require.NoError(t, os.WriteFile(configPath, configData, 0o600))

	ctx := apptest.FileContext(t, configPath)

	command := NewCommand()
	command.SetArgs([]string{"list", "--all"})

	err := command.ExecuteContext(ctx)
	require.Error(t, err)
	assert.ErrorContains(t, err, "401")
}

// TestRunRewriteListRejectsUnknownSortColumn verifies that an unknown sort
// column fails before any instance is contacted.
func TestRunRewriteListRejectsUnknownSortColumn(t *testing.T) {
	t.Parallel()

	server := newRewriteCommandServer(t, func(http.ResponseWriter, *http.Request) {
		t.Error("an unknown sort column must not reach the instance")
	})
	ctx := rewriteCommandContext(t, server.Listener.Addr().String())

	values := testRewriteListFlags()

	values.Sort = "bogus"

	err := runRewriteList(newRewriteCommand(ctx), nil, values)

	require.ErrorIs(t, err, output.ErrUnknownSortColumn)
	assert.Contains(t, err.Error(), "use one of domain, answer, status")
}

// TestRewriteListSortUsageNamesItsColumns verifies that the --sort help lists
// the columns the list table has.
func TestRewriteListSortUsageNamesItsColumns(t *testing.T) {
	t.Parallel()

	flag := newRewriteListCommand().Flags().Lookup("sort")

	require.NotNil(t, flag)
	assert.Equal(t, "sort column (domain, answer, status)", flag.Usage)
}
