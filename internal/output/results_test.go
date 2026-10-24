// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// TestWriteMutationResultsWritesOneLinePerInstance verifies the result line
// format and order.
func TestWriteMutationResultsWritesOneLinePerInstance(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	err := WriteMutationResults(&rendered, []app.MutationResult{
		{Instance: "alpha", Message: "Added client desk"},
		{Instance: "zulu", Message: "Added client desk"},
	})

	require.NoError(t, err)
	assert.Equal(t, "[alpha] Added client desk\n[zulu] Added client desk\n", rendered.String())
}

// TestWriteMutationResultsReportsWriteFailures verifies that every failed line is
// reported.
func TestWriteMutationResultsReportsWriteFailures(t *testing.T) {
	t.Parallel()

	err := WriteMutationResults(errorWriter{err: errWriteFailed}, []app.MutationResult{
		{Instance: "alpha", Message: "Added client desk"},
	})

	require.ErrorIs(t, err, errWriteFailed)
	assert.Contains(t, err.Error(), `write instance "alpha" result`)
}

// TestWriteInstanceHeaderSeparatesTables verifies that one selected instance gets
// no heading, and that every table after the first is preceded by a blank line.
func TestWriteInstanceHeaderSeparatesTables(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		position      int
		instanceCount int
		want          string
	}{
		"one instance":  {position: 0, instanceCount: 1, want: ""},
		"first table":   {position: 0, instanceCount: 2, want: "Instance: alpha\n"},
		"later table":   {position: 1, instanceCount: 2, want: "\nInstance: alpha\n"},
		"lone survivor": {position: 0, instanceCount: 3, want: "Instance: alpha\n"},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var rendered bytes.Buffer

			require.NoError(t, writeInstanceHeader(&rendered, test.position, test.instanceCount, "alpha"))
			assert.Equal(t, test.want, rendered.String())
		})
	}
}

// TestWriteInstanceHeaderReportsWriteFailures verifies that a failed separator
// and a failed heading are both reported.
func TestWriteInstanceHeaderReportsWriteFailures(t *testing.T) {
	t.Parallel()

	require.ErrorIs(t, writeInstanceHeader(errorWriter{err: errWriteFailed}, 1, 2, "alpha"), errWriteFailed)
	require.ErrorIs(t, writeInstanceHeader(errorWriter{err: errWriteFailed}, 0, 2, "alpha"), errWriteFailed)
}
