// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSortColumnsCheckAcceptsTableColumns verifies that a column of the table
// is accepted without regard to case, and that an empty column selects the
// default.
func TestSortColumnsCheckAcceptsTableColumns(t *testing.T) {
	t.Parallel()

	for _, column := range []string{"", "domain", "DOMAIN", "change"} {
		require.NoError(t, RewriteDiffSortColumns().Check(column), "column %q", column)
	}
}

// TestSortColumnsCheckRejectsOtherColumns verifies that a column the table
// lacks is refused with the accepted columns.
func TestSortColumnsCheckRejectsOtherColumns(t *testing.T) {
	t.Parallel()

	for _, column := range []string{AnswerSortColumn, StatusSortColumn, "bogus"} {
		err := RewriteDiffSortColumns().Check(column)

		require.ErrorIs(t, err, ErrUnknownSortColumn, "column %q", column)
		assert.Contains(t, err.Error(), "use one of domain, change")
	}
}

// TestSortColumnsUsageListsColumns verifies the help text of each rewrite
// table.
func TestSortColumnsUsageListsColumns(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "sort column (domain, answer, status)", RewriteListSortColumns().Usage())
	assert.Equal(t, "sort column (domain, change)", RewriteDiffSortColumns().Usage())
}

// TestSortRewriteSortsAnswersByAddress verifies that the answer column, in any
// case, sorts addresses by number rather than by label.
func TestSortRewriteSortsAnswersByAddress(t *testing.T) {
	t.Parallel()

	for _, column := range []string{"answer", "ANSWER"} {
		tableWriter := NewTableWriter("DOMAIN", "ANSWER")
		tableWriter.Row("a.example", "10.0.0.1")
		tableWriter.Row("b.example", "9.0.0.1")

		tableWriter.SortRewrite(column, "DOMAIN")
		tableWriter.Sort()

		assert.Equal(t, [][]string{
			{"b.example", "9.0.0.1"},
			{"a.example", "10.0.0.1"},
		}, tableWriter.rows, "column %q", column)
	}
}

// TestSortRewriteUsesDefaultColumn verifies that an empty column sorts by the
// default column with the domain comparator.
func TestSortRewriteUsesDefaultColumn(t *testing.T) {
	t.Parallel()

	tableWriter := NewTableWriter("DOMAIN", "ANSWER")
	tableWriter.Row("b.example.org", "192.0.2.1")
	tableWriter.Row("a.example.com", "192.0.2.2")

	tableWriter.SortRewrite("", "DOMAIN")
	tableWriter.Sort()

	assert.Equal(t, [][]string{
		{"a.example.com", "192.0.2.2"},
		{"b.example.org", "192.0.2.1"},
	}, tableWriter.rows)
}

// TestSortRewriteKeepsOrderForMissingColumn verifies that a column the table
// lacks leaves the rows in their original order.
func TestSortRewriteKeepsOrderForMissingColumn(t *testing.T) {
	t.Parallel()

	tableWriter := NewTableWriter("DOMAIN", "ANSWER")
	tableWriter.Row("b.example", "192.0.2.1")
	tableWriter.Row("a.example", "192.0.2.2")

	tableWriter.SortRewrite(ChangeSortColumn, "DOMAIN")
	tableWriter.Sort()

	assert.Equal(t, [][]string{
		{"b.example", "192.0.2.1"},
		{"a.example", "192.0.2.2"},
	}, tableWriter.rows)
}
