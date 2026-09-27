// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"slices"
	"strings"
)

// TableWriter builds aligned ASCII tables.
type TableWriter struct {
	// headers contains the column headings in display order.
	headers []string
	// rows contains the pending data rows in insertion order.
	rows [][]string
	// widths contains the rendered width of each column.
	widths []int
	// sortFunc compares complete rows when sorting is configured.
	sortFunc func(a, b []string) bool
}

// NewTableWriter creates a TableWriter with the given column headers.
//
// Parameters:
//   - headers: column header strings.
//
// Returns:
//   - *TableWriter: initialized table writer.
func NewTableWriter(headers ...string) *TableWriter {
	writer := &TableWriter{
		headers:  make([]string, len(headers)),
		widths:   make([]int, len(headers)),
		rows:     nil,
		sortFunc: nil,
	}
	copy(writer.headers, headers)

	for index, header := range headers {
		writer.widths[index] = len(header)
	}

	return writer
}

// Print sorts and writes the table to standard output, ignoring write errors.
func (t *TableWriter) Print() {
	_, err := t.WriteTo(os.Stdout)
	if err != nil {
		return
	}
}

// Row appends a data row. Extra columns are ignored; missing columns are padded.
//
// Parameters:
//   - values: row values aligned to headers.
func (t *TableWriter) Row(values ...string) {
	if len(values) == 0 {
		return
	}

	row := make([]string, 0, len(t.headers))
	for index := range t.headers {
		value := ""
		if index < len(values) {
			value = values[index]
		}

		row = append(row, value)
		if len(value) > t.widths[index] {
			t.widths[index] = len(value)
		}
	}

	t.rows = append(t.rows, row)
}

// Sort sorts rows by the configured column and less function attached via SortByHeader.
func (t *TableWriter) Sort() {
	if t.sortFunc == nil {
		return
	}

	slices.SortStableFunc(t.rows, func(left, right []string) int {
		if t.sortFunc(left, right) {
			return -1
		}

		if t.sortFunc(right, left) {
			return 1
		}

		return 0
	})
}

// SortByHeader sets sorting by a named column using a domain-aware less
// factory.
//
// The factory is called with the matched column index so the
// returned less function operates on that column.
//
// Parameters:
//   - column: header name to sort by.
//   - domainLess: factory that returns a less function for the matched index.
func (t *TableWriter) SortByHeader(column string, domainLess func(index int) func(a, b []string) bool) {
	if column == "" || domainLess == nil {
		return
	}

	for index, header := range t.headers {
		if strings.EqualFold(header, column) {
			t.sortFunc = domainLess(index)

			return
		}
	}
}

// WriteTo sorts and renders the table to the provided writer.
//
// Parameters:
//   - writer: destination for the rendered t.
//
// Returns:
//   - int64: number of bytes written.
//   - error: non-nil when the destination rejects output.
func (t *TableWriter) WriteTo(writer io.Writer) (int64, error) {
	t.Sort()

	lines := make([]string, 0, len(t.rows)+2)

	lines = append(lines, t.renderLine(t.headers...))

	separator := make([]string, 0, len(t.widths))
	for _, width := range t.widths {
		separator = append(separator, strings.Repeat("-", width)+"  ")
	}

	lines = append(lines, strings.Join(separator, ""))
	for _, row := range t.rows {
		lines = append(lines, t.renderLine(row...))
	}

	content := strings.Join(lines, "\n") + "\n"
	written, err := io.WriteString(writer, content)
	if err == nil && written != len(content) {
		err = io.ErrShortWrite
	}

	if err != nil {
		return int64(written), fmt.Errorf("write table: %w", err)
	}

	return int64(written), nil
}

// renderLine returns a joined string with each column padded to width.
//
// Parameters:
//   - values: column values for the row.
//
// Returns:
//   - string: padded row string.
func (t *TableWriter) renderLine(values ...string) string {
	var builder strings.Builder

	for index, value := range values {
		if index > 0 {
			_, _ = builder.WriteString("  ")
		}

		_, _ = fmt.Fprintf(&builder, "%-*s", t.widths[index], value)
	}

	return builder.String()
}

// DomainLess returns a less function for domain-aware sorting from right to left
// on the given column index.
//
// Wildcard entries are normalized so that "*." is treated like an empty
// subdomain, grouping wildcards with the bare domain.
//
// Parameters:
//   - index: column index to sort by.
//
// Returns:
//   - func(a, b []string) bool: less function for domain-aware comparison.
func DomainLess(index int) func(leftRow, rightRow []string) bool {
	return func(leftRow, rightRow []string) bool {
		if len(leftRow) <= index || len(rightRow) <= index {
			return true
		}

		left := reverseDomainLabels(leftRow[index])
		right := reverseDomainLabels(rightRow[index])
		if left != right {
			return left < right
		}

		return leftRow[index] < rightRow[index]
	}
}

// AnswerLess returns a less function for IP-aware sorting on the given column
// index.
//
// IPv4 addresses sort before IPv6. Within each family, addresses are
// compared numerically octet/hextet by octet/hextet.
// Non-IP values fall back to lexicographic string comparison.
//
// Parameters:
//   - index: column index to sort by.
//
// Returns:
//   - func(a, b []string) bool: less function for IP-aware comparison.
func AnswerLess(index int) func(leftRow, rightRow []string) bool {
	return func(leftRow, rightRow []string) bool {
		if len(leftRow) <= index || len(rightRow) <= index {
			return true
		}

		return compareIPs(leftRow[index], rightRow[index])
	}
}

// compareIPs compares two IP address strings numerically.
//
// IPv4 addresses sort before IPv6. Within each family, addresses are compared
// numerically. Non-IP values fall back to lexicographic comparison.
//
// Parameters:
//   - leftAnswer: first IP string.
//   - rightAnswer: second IP string.
//
// Returns:
//   - bool: true when leftAnswer sorts before rightAnswer.
func compareIPs(leftAnswer, rightAnswer string) bool {
	leftIP := net.ParseIP(answerValue(leftAnswer))
	rightIP := net.ParseIP(answerValue(rightAnswer))
	if leftIP == nil || rightIP == nil {
		return leftAnswer < rightAnswer
	}

	leftIPv4 := leftIP.To4()
	rightIPv4 := rightIP.To4()

	switch {
	case leftIPv4 != nil && rightIPv4 == nil:
		return true
	case leftIPv4 == nil && rightIPv4 != nil:
		return false
	case leftIPv4 != nil:
		return bytes.Compare(leftIPv4, rightIPv4) < 0
	default:
		return bytes.Compare(leftIP, rightIP) < 0
	}
}

// answerValue extracts the raw IP portion from a formatted answer string.
//
// A "-" placeholder becomes empty, and a " <text>" suffix is stripped.
//
// Parameters:
//   - formattedAnswer: formatted answer string.
//
// Returns:
//   - string: raw IP or answer value.
func answerValue(formattedAnswer string) string {
	formattedAnswer = strings.TrimSpace(formattedAnswer)
	if formattedAnswer == "-" {
		return ""
	}

	if before, _, ok := strings.Cut(formattedAnswer, " "); ok {
		return before
	}

	return formattedAnswer
}

// reverseDomainLabels reverses the dot-separated labels of a domain for
// right-to-left sorting.
//
// A leading "*." wildcard is normalized away so that wildcard entries group
// with the bare domain.
//
// Parameters:
//   - domain: domain name to reverse.
//
// Returns:
//   - string: reversed domain labels.
func reverseDomainLabels(domain string) string {
	domain = strings.TrimPrefix(domain, "*.")

	parts := strings.Split(domain, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}

	return strings.Join(parts, ".")
}
