// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"cmp"
	"fmt"
	"io"
	"net/netip"
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

// answerFamily ranks the kinds of rewrite answer in sort order.
type answerFamily int

// Answer families in the order they sort.
const (
	// IPv4Answer is an IPv4 address, including an IPv4-mapped IPv6 address.
	ipv4Answer answerFamily = iota
	// IPv6Answer is any other IP address.
	ipv6Answer
	// OtherAnswer is a value that is not an IP address, such as a domain name.
	otherAnswer
)

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
		left := columnValue(leftRow, index)
		right := columnValue(rightRow, index)

		return cmp.Or(
			strings.Compare(reverseDomainLabels(left), reverseDomainLabels(right)),
			strings.Compare(left, right),
		) < 0
	}
}

// AnswerLess returns a less function for IP-aware sorting on the given column
// index.
//
// IPv4 addresses sort first and IPv6 addresses next, each family in numeric
// order. Every value that is not an IP address, such as a domain name, sorts
// after the addresses in lexicographic order. The order is total, so the sorted
// rows never depend on the order they arrived in.
//
// Parameters:
//   - index: column index to sort by.
//
// Returns:
//   - func(a, b []string) bool: less function for IP-aware comparison.
func AnswerLess(index int) func(leftRow, rightRow []string) bool {
	return func(leftRow, rightRow []string) bool {
		return compareAnswers(columnValue(leftRow, index), columnValue(rightRow, index)) < 0
	}
}

// compareAnswers orders two formatted answers.
//
// Answers compare by family first, then by address within a family. Any
// remaining tie, such as between two values that are not addresses, falls back
// to the formatted text.
//
// Parameters:
//   - leftAnswer: first formatted answer.
//   - rightAnswer: second formatted answer.
//
// Returns:
//   - int: a negative number when leftAnswer sorts first, a positive number when
//     rightAnswer sorts first, and zero when they are equal.
func compareAnswers(leftAnswer, rightAnswer string) int {
	leftFamily, leftAddr := parseAnswer(leftAnswer)
	rightFamily, rightAddr := parseAnswer(rightAnswer)

	return cmp.Or(
		cmp.Compare(leftFamily, rightFamily),
		leftAddr.Compare(rightAddr),
		strings.Compare(leftAnswer, rightAnswer),
	)
}

// parseAnswer reports the family and address of one formatted answer.
//
// An IPv4-mapped IPv6 address is unmapped, so it sorts with the IPv4 address it
// carries.
//
// Parameters:
//   - formattedAnswer: formatted answer string.
//
// Returns:
//   - answerFamily: the family the answer sorts in.
//   - [netip.Addr]: the parsed address, or the zero address for a value that is
//     not an IP address.
func parseAnswer(formattedAnswer string) (answerFamily, netip.Addr) {
	addr, err := netip.ParseAddr(answerValue(formattedAnswer))
	if err != nil {
		return otherAnswer, netip.Addr{}
	}

	addr = addr.Unmap()
	if addr.Is4() {
		return ipv4Answer, addr
	}

	return ipv6Answer, addr
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

// columnValue returns one column of a row.
//
// A row too short to hold the column reads as an empty value, so it sorts
// consistently instead of comparing before every other row.
//
// Parameters:
//   - row: table row.
//   - index: column index.
//
// Returns:
//   - string: the column value, or an empty string when the row lacks it.
func columnValue(row []string, index int) string {
	if index < 0 || index >= len(row) {
		return ""
	}

	return row[index]
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
