// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package credentials

import (
	"os"
)

// OSEnvReader reads credentials from the environment of the CLI process.
//
// The reader is the supported credential source for headless systems, SSH
// sessions, and containers, where no operating system credential store session
// exists. Only the configured variable is read, and an unset variable is an
// error reported by the resolver rather than a fallback to another source.
type OSEnvReader struct{}

// NewOSEnvReader creates a process environment credential reader.
//
// Returns:
//   - *OSEnvReader: reader over the environment of the CLI process.
func NewOSEnvReader() *OSEnvReader {
	return &OSEnvReader{}
}

// Lookup returns the value of exactly the requested variable.
//
// A variable that is set to an empty value is reported as set, so an operator
// can distinguish an empty secret from a missing one.
//
// Parameters:
//   - name: environment variable name.
//
// Returns:
//   - string: the variable value, or an empty string when it is unset.
//   - bool: true when the variable is set, including when it is set to an empty
//     value.
func (*OSEnvReader) Lookup(name string) (string, bool) {
	return os.LookupEnv(name)
}
