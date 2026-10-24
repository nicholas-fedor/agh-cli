// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// TestRunRewriteDiffRejectsListOnlySortColumns verifies that the answer and
// status columns, which the diff table lacks, fail before any instance is
// contacted.
func TestRunRewriteDiffRejectsListOnlySortColumns(t *testing.T) {
	t.Parallel()

	server := newRewriteCommandServer(t, func(http.ResponseWriter, *http.Request) {
		t.Error("an unknown sort column must not reach the instance")
	})
	ctx := rewriteCommandContext(t, server.Listener.Addr().String())

	for _, column := range []string{output.AnswerSortColumn, output.StatusSortColumn} {
		values := testRewriteDiffFlags()

		values.Sort = column

		err := runRewriteDiff(newRewriteCommand(ctx), nil, values)

		require.ErrorIs(t, err, output.ErrUnknownSortColumn, "column %q", column)
		assert.Contains(t, err.Error(), "use one of domain, change")
	}
}

// TestRewriteDiffSortUsageNamesItsColumns verifies that the --sort help lists
// the columns the diff table has.
func TestRewriteDiffSortUsageNamesItsColumns(t *testing.T) {
	t.Parallel()

	flag := newRewriteDiffCommand().Flags().Lookup("sort")

	require.NotNil(t, flag)
	assert.Equal(t, "sort column (domain, change)", flag.Usage)
}
