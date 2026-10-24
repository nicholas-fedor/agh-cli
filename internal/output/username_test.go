// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

// usernameTestReport is a report with one configured and one unset username.
var usernameTestReport = credentials.UsernameReport{Instances: []credentials.UsernameStatus{
	{Instance: "alpha", Username: "admin"},
	{Instance: "zulu", Username: ""},
}}

// TestWriteUsernameStatusTextLabelsUnsetUsername verifies the text report.
func TestWriteUsernameStatusTextLabelsUnsetUsername(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	require.NoError(t, WriteUsernameStatusText(&rendered, usernameTestReport))
	assert.Equal(t, "instance \"alpha\": username \"admin\"\ninstance \"zulu\": (unset)\n", rendered.String())
}

// TestWriteUsernameStatusJSONOmitsUnsetUsername verifies the JSON report.
func TestWriteUsernameStatusJSONOmitsUnsetUsername(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	require.NoError(t, WriteUsernameStatusJSON(&rendered, usernameTestReport))
	assert.JSONEq(t, `{"instances":[{"instance":"alpha","username":"admin"},{"instance":"zulu"}]}`, rendered.String())
}

// TestWriteUsernameOutcomesWriteOneLine verifies the set and cleared outcomes.
func TestWriteUsernameOutcomesWriteOneLine(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	require.NoError(t, WriteUsernameSet(&rendered, "alpha", "admin"))
	require.NoError(t, WriteUsernameCleared(&rendered, "alpha"))
	assert.Equal(t,
		"Username for instance \"alpha\" set to \"admin\".\nUsername for instance \"alpha\" cleared.\n",
		rendered.String(),
	)
}

// TestWriteUsernameWritersReportWriteFailures verifies that every username writer
// reports a destination that rejects output.
func TestWriteUsernameWritersReportWriteFailures(t *testing.T) {
	t.Parallel()

	failing := errorWriter{err: errWriteFailed}

	require.ErrorIs(t, WriteUsernameStatusText(failing, usernameTestReport), errWriteFailed)
	require.ErrorIs(t, WriteUsernameStatusJSON(failing, usernameTestReport), errWriteFailed)
	require.ErrorIs(t, WriteUsernameSet(failing, "alpha", "admin"), errWriteFailed)
	require.ErrorIs(t, WriteUsernameCleared(failing, "alpha"), errWriteFailed)
}
