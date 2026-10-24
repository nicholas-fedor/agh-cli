// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package prompt

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// TerminalInput is command input that answers the terminal questions itself.
//
// A command's input is normally a file, and the operating system reports
// whether it is a terminal and reads it without echoing. An input that
// implements this interface answers instead, which lets a test drive a hidden
// prompt through the command's input.
type TerminalInput interface {
	io.Reader

	// IsTerminal reports whether the input is a terminal.
	//
	// Returns:
	//   - bool: true when a prompt is possible.
	IsTerminal() bool
	// ReadHidden reads one line without echoing it.
	//
	// Returns:
	//   - []byte: the line read, without its terminator.
	//   - error: the read error.
	ReadHidden() ([]byte, error)
}

// Terminal reads operator input from one command's input and writes its prompts
// to one command's error stream.
type Terminal struct {
	// in supplies the operator input.
	in io.Reader
	// out receives the prompts.
	out io.Writer
	// isTerminal reports whether in is a terminal, which decides whether a
	// prompt is possible.
	isTerminal func() bool
	// readHidden reads from in without echoing.
	readHidden func() ([]byte, error)
}

// ErrNotAFile reports that standard input is not a terminal file descriptor, so a
// hidden prompt is impossible.
var ErrNotAFile = errors.New("standard input is not a terminal file")

// New returns a Terminal over the supplied streams.
//
// An input that implements [TerminalInput] answers the terminal questions
// itself. Any other input is asked through the operating system.
//
// Parameters:
//   - in: command input.
//   - out: destination for the prompts, normally the error stream.
//
// Returns:
//   - Terminal: input bound to the streams.
func New(in io.Reader, out io.Writer) Terminal {
	if input, ok := in.(TerminalInput); ok {
		return Terminal{in: in, out: out, isTerminal: input.IsTerminal, readHidden: input.ReadHidden}
	}

	return Terminal{
		in:         in,
		out:        out,
		isTerminal: func() bool { return fileIsTerminal(in) },
		readHidden: func() ([]byte, error) { return readHiddenFile(in) },
	}
}

// fileIsTerminal reports whether a reader is a file connected to a terminal.
//
// Parameters:
//   - reader: command input.
//
// Returns:
//   - bool: true when the input is connected to a terminal.
func fileIsTerminal(reader io.Reader) bool {
	descriptor, err := fileDescriptor(reader)
	if err != nil {
		return false
	}

	return term.IsTerminal(descriptor)
}

// readHiddenFile reads one line from a terminal file without echoing it.
//
// Parameters:
//   - reader: terminal-backed command input.
//
// Returns:
//   - []byte: the line read, without its terminator.
//   - error: a wrapped [ErrNotAFile] when the reader is not a terminal file, or
//     the terminal read error.
func readHiddenFile(reader io.Reader) ([]byte, error) {
	descriptor, err := fileDescriptor(reader)
	if err != nil {
		return nil, fmt.Errorf("locate terminal: %w", err)
	}

	line, err := term.ReadPassword(descriptor)
	if err != nil {
		return nil, fmt.Errorf("read terminal: %w", err)
	}

	return line, nil
}

// fileDescriptor returns the descriptor of a terminal-backed reader.
//
// Callers check fileIsTerminal first, so an unusable reader is reported by
// [ErrNotAFile] rather than silently read.
//
// Parameters:
//   - reader: command input.
//
// Returns:
//   - int: the file descriptor of the reader.
//   - error: [ErrNotAFile] when the reader is not a terminal file.
func fileDescriptor(reader io.Reader) (int, error) {
	file, ok := reader.(*os.File)
	if !ok {
		return 0, ErrNotAFile
	}

	return int(file.Fd()), nil
}
