// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/client"
)

// TestWriteClientListSeparatesInstances verifies the client tables, their
// headings, and the single blank line between them.
func TestWriteClientListSeparatesInstances(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	err := WriteClientList(&rendered, []app.ClientListResult{
		{Instance: "alpha", Rows: []client.Row{{Name: "desk", Automatic: false}}, InstanceCount: 2},
		{Instance: "zulu", Rows: []client.Row{{Name: "laptop", Automatic: true}}, InstanceCount: 2},
	})

	require.NoError(t, err)
	assert.Equal(t,
		"Instance: alpha\n"+
			"INSTANCE  NAME  TYPE  \n"+
			"--------  ----  ------  \n"+
			"alpha     desk  static\n"+
			"\n"+
			"Instance: zulu\n"+
			"INSTANCE  NAME    TYPE\n"+
			"--------  ------  ----  \n"+
			"zulu      laptop  auto\n",
		rendered.String(),
	)
}

// TestWriteClientListReportsWriteFailures verifies that a table that cannot be
// written names its instance.
func TestWriteClientListReportsWriteFailures(t *testing.T) {
	t.Parallel()

	err := WriteClientList(errorWriter{err: errWriteFailed}, []app.ClientListResult{
		{Instance: "alpha", Rows: nil, InstanceCount: 1},
	})

	require.ErrorIs(t, err, errWriteFailed)
	assert.Contains(t, err.Error(), `write instance "alpha"`)
}
