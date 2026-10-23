// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/app/apptest"
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

// TestWriteRewriteListsSeparatesInstances verifies that the instance tables are
// separated by exactly one blank line, with none before the first table.
func TestWriteRewriteListsSeparatesInstances(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	command := &cobra.Command{}
	command.SetOut(&output)

	err := writeRewriteLists(command, []app.RewriteListResult{
		{Instance: "alpha", Rules: []app.RewriteRule{}, InstanceCount: 2},
		{Instance: "zulu", Rules: []app.RewriteRule{}, InstanceCount: 2},
	}, "")

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(output.String(), "Instance: alpha\n"))
	assert.Contains(t, output.String(), "\n\nInstance: zulu\n")
	assert.NotContains(t, output.String(), "\n\n\n")
}

// TestWriteRewriteListsOmitsHeaderForOneInstance verifies that a single
// selected instance is rendered without a separator or an instance header.
func TestWriteRewriteListsOmitsHeaderForOneInstance(t *testing.T) {
	t.Parallel()

	var output bytes.Buffer

	command := &cobra.Command{}
	command.SetOut(&output)

	err := writeRewriteLists(command, []app.RewriteListResult{
		{Instance: "alpha", Rules: []app.RewriteRule{}, InstanceCount: 1},
	}, "")

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(output.String(), "INSTANCE"))
	assert.NotContains(t, output.String(), "Instance: ")
}
