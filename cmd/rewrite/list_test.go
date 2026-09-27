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

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListReturnsInstanceFailure verifies that rewrite list fails when an instance request fails.
//
//nolint:paralleltest // The test mutates the process-global Viper instance.
func TestListReturnsInstanceFailure(t *testing.T) {
	viper.Reset()

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
	viper.SetConfigFile(configPath)
	require.NoError(t, viper.ReadInConfig())

	t.Cleanup(func() {
		viper.Reset()
	})

	command := NewCommand()
	command.SetArgs([]string{"list", "--all"})

	err := command.ExecuteContext(t.Context())
	require.Error(t, err)
	assert.ErrorContains(t, err, "401")
}
