// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// TestWriteRewriteListsSeparatesInstances verifies that the instance tables are
// separated by exactly one blank line, with none before the first table.
func TestWriteRewriteListsSeparatesInstances(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	err := WriteRewriteLists(&rendered, []app.RewriteListResult{
		{Instance: "alpha", Rules: []app.RewriteRule{}, InstanceCount: 2},
		{Instance: "zulu", Rules: []app.RewriteRule{}, InstanceCount: 2},
	}, "")

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(rendered.String(), "Instance: alpha\n"))
	assert.Contains(t, rendered.String(), "\n\nInstance: zulu\n")
	assert.NotContains(t, rendered.String(), "\n\n\n")
}

// TestWriteRewriteListsOmitsHeaderForOneInstance verifies that a single selected
// instance is written without a separator or an instance heading, and that its
// rules sort by the requested column.
func TestWriteRewriteListsOmitsHeaderForOneInstance(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	err := WriteRewriteLists(&rendered, []app.RewriteListResult{{
		Instance: "alpha",
		Rules: []app.RewriteRule{
			{Domain: "a.example", Answer: "10.0.0.1", Enabled: true},
			{Domain: "b.example", Answer: "9.0.0.1", Enabled: false},
		},
		InstanceCount: 1,
	}}, AnswerSortColumn)

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(rendered.String(), "INSTANCE"))
	assert.NotContains(t, rendered.String(), "Instance: ")
	assert.Less(t, strings.Index(rendered.String(), "9.0.0.1"), strings.Index(rendered.String(), "10.0.0.1"))
}

// TestWriteRewriteDiffSortsByChange verifies that the change column orders the
// diff rows by the kind of difference, and that a missing side is a placeholder.
func TestWriteRewriteDiffSortsByChange(t *testing.T) {
	t.Parallel()

	rule := &app.RewriteRule{Domain: "", Answer: "192.0.2.1", Enabled: true}

	var rendered bytes.Buffer

	err := WriteRewriteDiff(&rendered, app.RewriteDiffResult{
		Mode:          app.RewriteDiffFile,
		InstanceNames: []string{"lab"},
		Diff: app.RewriteDiff{
			Added:    []app.RewriteDiffEntry{{Domain: "c.example", Old: nil, New: rule, Change: "added"}},
			Removed:  []app.RewriteDiffEntry{{Domain: "a.example", Old: rule, New: nil, Change: "removed"}},
			Modified: []app.RewriteDiffEntry{{Domain: "b.example", Old: rule, New: rule, Change: "modified"}},
		},
	}, ChangeSortColumn)

	require.NoError(t, err)
	assert.Contains(t, rendered.String(), "DOMAIN     LOCAL                REMOTE               CHANGE")
	assert.Contains(t, rendered.String(), "c.example  -                    192.0.2.1 (enabled)  added")
	assert.Less(t, strings.Index(rendered.String(), "c.example"), strings.Index(rendered.String(), "b.example"))
	assert.Less(t, strings.Index(rendered.String(), "b.example"), strings.Index(rendered.String(), "a.example"))
}

// TestWriteRewriteDiffNamesComparedInstances verifies that comparing two
// instances names the side columns after them.
func TestWriteRewriteDiffNamesComparedInstances(t *testing.T) {
	t.Parallel()

	var rendered bytes.Buffer

	err := WriteRewriteDiff(&rendered, app.RewriteDiffResult{
		Mode:          app.RewriteDiffInstances,
		InstanceNames: []string{"alpha", "zulu"},
		Diff:          app.RewriteDiff{Added: nil, Removed: nil, Modified: nil},
	}, "")

	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(rendered.String(), "DOMAIN  ALPHA  ZULU  CHANGE"))
}

// TestWriteRewriteSettingsWritesOneLinePerInstance verifies the settings line
// format and that a failed line is reported.
func TestWriteRewriteSettingsWritesOneLinePerInstance(t *testing.T) {
	t.Parallel()

	results := []app.RewriteSettingsResult{{Instance: "alpha", Enabled: true}, {Instance: "zulu", Enabled: false}}

	var rendered bytes.Buffer

	require.NoError(t, WriteRewriteSettings(&rendered, results))
	assert.Equal(t, "[alpha] {\"enabled\":true}\n[zulu] {\"enabled\":false}\n", rendered.String())
	require.ErrorIs(t, WriteRewriteSettings(errorWriter{err: errWriteFailed}, results), errWriteFailed)
}

// TestWriteRewriteWritersReportWriteFailures verifies that the list and diff
// tables report a destination that rejects output.
func TestWriteRewriteWritersReportWriteFailures(t *testing.T) {
	t.Parallel()

	listErr := WriteRewriteLists(errorWriter{err: errWriteFailed}, []app.RewriteListResult{
		{Instance: "alpha", Rules: nil, InstanceCount: 1},
	}, "")
	require.ErrorIs(t, listErr, errWriteFailed)

	diffErr := WriteRewriteDiff(errorWriter{err: errWriteFailed}, app.RewriteDiffResult{
		Mode:          app.RewriteDiffFile,
		InstanceNames: []string{"lab"},
		Diff:          app.RewriteDiff{Added: nil, Removed: nil, Modified: nil},
	}, "")
	require.ErrorIs(t, diffErr, errWriteFailed)
}
