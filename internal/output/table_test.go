// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"bytes"
	"errors"
	"io"
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
