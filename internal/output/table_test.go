// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"errors"
	"io"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errorWriter rejects every write with a configured error.
type errorWriter struct {
	// err is returned without writing any bytes.
	err error
}

// shortWriter accepts fewer bytes than requested without reporting an error.
type shortWriter struct{}

// errWriteFailed identifies an intentional output failure.
var errWriteFailed = errors.New("write failed")

// Write returns the configured writer error without writing data.
//
// Parameters:
//   - _: output bytes intentionally ignored.
//
// Returns:
//   - int: number of bytes written, always zero.
//   - error: configured writer error.
func (w errorWriter) Write(_ []byte) (int, error) {
	return 0, w.err
}

// Write reports one fewer written byte than requested without an error.
//
// Parameters:
//   - data: bytes the caller attempted to write.
//
// Returns:
//   - int: one fewer than the length of data.
//   - error: always nil.
func (shortWriter) Write(data []byte) (int, error) {
	return len(data) - 1, nil
}

// TestTableWriterWriteTo verifies injected rendering preserves table output.
func TestTableWriterWriteTo(t *testing.T) {
	t.Parallel()

	tableWriter := NewTableWriter("DOMAIN", "STATUS")
	tableWriter.Row("example.org", "disabled")
	tableWriter.Row("example.com", "enabled")
	tableWriter.SortByHeader("domain", DomainLess)

	var buffer bytes.Buffer

	written, err := tableWriter.WriteTo(&buffer)
	require.NoError(t, err)
	assert.Equal(t, int64(buffer.Len()), written)
	assert.Equal(
		t,
		"DOMAIN       STATUS  \n"+
			"-----------  --------  \n"+
			"example.com  enabled \n"+
			"example.org  disabled\n",
		buffer.String(),
	)
}

// TestTableWriterWriteToReturnsWriterError verifies writer failures propagate.
func TestTableWriterWriteToReturnsWriterError(t *testing.T) {
	t.Parallel()

	tableWriter := NewTableWriter("DOMAIN")
	tableWriter.Row("example.com")

	written, err := tableWriter.WriteTo(errorWriter{err: errWriteFailed})
	require.Error(t, err)
	assert.Zero(t, written)
	assert.ErrorIs(t, err, errWriteFailed)
}

// TestTableWriterWriteToRejectsShortWrite verifies incomplete writes fail.
func TestTableWriterWriteToRejectsShortWrite(t *testing.T) {
	t.Parallel()

	tableWriter := NewTableWriter("DOMAIN")
	tableWriter.Row("example.com")

	written, err := tableWriter.WriteTo(shortWriter{})
	require.Error(t, err)
	assert.Positive(t, written)
	assert.ErrorIs(t, err, io.ErrShortWrite)
}

// TestAnswerLessOrdersFamiliesThenValues verifies that answers sort as IPv4,
// then IPv6, then every other value, and that the sorted order is the same
// whatever order the rows arrived in.
func TestAnswerLessOrdersFamiliesThenValues(t *testing.T) {
	t.Parallel()

	want := []string{
		"9.0.0.1",
		"10.0.0.1",
		"192.0.2.1",
		"::ffff:192.0.2.1",
		"::1",
		"2001:db8::1",
		"",
		"1password.example",
		"a.example",
	}

	for shift := range want {
		answers := append(slices.Clone(want[shift:]), want[:shift]...)
		slices.Reverse(answers)

		tableWriter := NewTableWriter("DOMAIN", "ANSWER")
		for _, answer := range answers {
			tableWriter.Row("example.com", answer)
		}

		tableWriter.SortByHeader("answer", AnswerLess)
		tableWriter.Sort()

		got := make([]string, 0, len(tableWriter.rows))
		for _, row := range tableWriter.rows {
			got = append(got, row[1])
		}

		assert.Equal(t, want, got, "input order %q", answers)
	}
}

// TestParseAnswerReadsFormattedAnswers verifies that a formatted answer is
// classified by the address it starts with.
func TestParseAnswerReadsFormattedAnswers(t *testing.T) {
	t.Parallel()

	tests := map[string]answerFamily{
		"192.0.2.1":             ipv4Answer,
		"192.0.2.1 (enabled)":   ipv4Answer,
		"::ffff:192.0.2.1":      ipv4Answer,
		"2001:db8::1":           ipv6Answer,
		" 2001:db8::1 ":         ipv6Answer,
		"-":                     otherAnswer,
		"example.org":           otherAnswer,
		"example.org (enabled)": otherAnswer,
	}

	for answer, want := range tests {
		family, _ := parseAnswer(answer)
		assert.Equal(t, want, family, "answer %q", answer)
	}
}

// TestRowComparatorsAreStrictOrders verifies that the domain and answer
// comparators never contradict themselves, including for rows too short to
// hold the sort column, because a contradictory comparator lets the sorted
// output depend on the input order.
func TestRowComparatorsAreStrictOrders(t *testing.T) {
	t.Parallel()

	rows := [][]string{
		{},
		{"example.com"},
		{"example.com", ""},
		{"example.com", "9.0.0.1"},
		{"example.com", "10.0.0.1"},
		{"example.com", "::1"},
		{"example.com", "1password.example"},
		{"example.com", "*.example.org"},
		{"example.com", "example.org"},
		{"example.com", "a.example.org"},
	}

	comparators := map[string]func(index int) func(leftRow, rightRow []string) bool{
		"domain": DomainLess,
		"answer": AnswerLess,
	}

	for name, comparator := range comparators {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			assertStrictOrder(t, comparator(1), rows)
		})
	}
}

// assertStrictOrder checks that less is irreflexive, asymmetric, and transitive
// over every combination of rows.
//
// Parameters:
//   - less: row comparator under test.
//   - rows: rows to compare in every combination.
func assertStrictOrder(t *testing.T, less func(leftRow, rightRow []string) bool, rows [][]string) {
	t.Helper()

	for _, left := range rows {
		assert.False(t, less(left, left), "%q sorts before itself", left)

		for _, right := range rows {
			assertAsymmetric(t, less, left, right)
			assertTransitive(t, less, left, right, rows)
		}
	}
}

// assertAsymmetric checks that two rows never each sort before the other.
//
// Parameters:
//   - less: row comparator under test.
//   - left: first row.
//   - right: second row.
func assertAsymmetric(t *testing.T, less func(leftRow, rightRow []string) bool, left, right []string) {
	t.Helper()

	if less(left, right) {
		assert.False(t, less(right, left), "%q and %q each sort first", left, right)
	}
}

// assertTransitive checks that a row sorting before right also sorts before
// every row that right sorts before.
//
// Parameters:
//   - less: row comparator under test.
//   - left: first row.
//   - right: second row.
//   - rows: candidate third rows.
func assertTransitive(
	t *testing.T,
	less func(leftRow, rightRow []string) bool,
	left []string,
	right []string,
	rows [][]string,
) {
	t.Helper()

	if !less(left, right) {
		return
	}

	for _, third := range rows {
		if less(right, third) {
			assert.True(t, less(left, third), "%q < %q < %q is not transitive", left, right, third)
		}
	}
}
