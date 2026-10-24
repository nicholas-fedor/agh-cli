// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"errors"
	"fmt"
	"slices"
	"strings"
)

// SortColumns lists the columns a table can be sorted by, in help order.
type SortColumns []string

// Sort columns of the rewrite tables.
const (
	// DomainSortColumn sorts by the rewritten domain.
	DomainSortColumn = "domain"
	// AnswerSortColumn sorts by the rewrite answer.
	AnswerSortColumn = "answer"
	// StatusSortColumn sorts by the enabled state of a rule.
	StatusSortColumn = "status"
	// ChangeSortColumn sorts by the kind of difference.
	ChangeSortColumn = "change"
)

// ErrUnknownSortColumn reports a sort column the table does not have.
var ErrUnknownSortColumn = errors.New("unknown sort column")

// RewriteListSortColumns returns the columns the rewrite list table sorts by.
//
// Returns:
//   - SortColumns: the domain, answer, and status columns.
func RewriteListSortColumns() SortColumns {
	return SortColumns{DomainSortColumn, AnswerSortColumn, StatusSortColumn}
}

// RewriteDiffSortColumns returns the columns the rewrite diff table sorts by.
//
// The local and remote columns are left out, because comparing two instances
// renames them after the instances.
//
// Returns:
//   - SortColumns: the domain and change columns.
func RewriteDiffSortColumns() SortColumns {
	return SortColumns{DomainSortColumn, ChangeSortColumn}
}

// Check refuses a sort column the table does not have.
//
// Columns match without regard to case, as the table headers do. An empty
// column selects the table's default column.
//
// Parameters:
//   - column: requested sort column.
//
// Returns:
//   - error: an error wrapping [ErrUnknownSortColumn] that names the accepted
//     columns when column is not one of them.
func (c SortColumns) Check(column string) error {
	if column == "" || slices.ContainsFunc(c, func(name string) bool {
		return strings.EqualFold(name, column)
	}) {
		return nil
	}

	return fmt.Errorf("%w %q: use one of %s", ErrUnknownSortColumn, column, strings.Join(c, ", "))
}

// Usage describes the sort columns for command help.
//
// Returns:
//   - string: the help text listing the columns.
func (c SortColumns) Usage() string {
	return "sort column (" + strings.Join(c, ", ") + ")"
}

// SortRewrite orders a rewrite table by one column.
//
// The answer column sorts with [AnswerLess], so addresses sort by number. Every
// other column sorts with [DomainLess]. A column the table does not have leaves
// the rows in their original order.
//
// Parameters:
//   - column: requested sort column, or an empty string for defaultColumn.
//   - defaultColumn: header the table sorts by when no column is requested.
func (t *TableWriter) SortRewrite(column, defaultColumn string) {
	if column == "" {
		column = defaultColumn
	}

	if strings.EqualFold(column, AnswerSortColumn) {
		t.SortByHeader(column, AnswerLess)

		return
	}

	t.SortByHeader(column, DomainLess)
}
