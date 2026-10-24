// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"fmt"
)

// RewriteValue is the output representation of a rewrite rule's answer and
// enabled state.
type RewriteValue struct {
	// Answer is the value returned for the rewritten domain.
	Answer string
	// Enabled reports whether the rewrite rule is active.
	Enabled bool
}

// FormatRewrite formats a neutral rewrite value for display.
//
// Parameters:
//   - value: rewrite value to format.
//
// Returns:
//   - string: formatted answer and enabled state.
func FormatRewrite(value RewriteValue) string {
	return fmt.Sprintf("%s (%s)", value.Answer, FormatEnabled(value.Enabled))
}

// FormatEnabled returns "enabled" or "disabled" for a boolean value.
//
// Parameters:
//   - state: boolean state to format.
//
// Returns:
//   - string: "enabled" or "disabled".
func FormatEnabled[T ~bool](state T) string {
	if state {
		return "enabled"
	}

	return "disabled"
}

// FormatRewriteStatus returns the display status for a rewrite entry.
//
// Parameters:
//   - enabled: boolean state of the rewrite entry.
//
// Returns:
//   - string: "enabled" or "disabled".
func FormatRewriteStatus(enabled bool) string {
	return FormatEnabled(enabled)
}

// FormatClientType returns the client type label for display.
//
// Parameters:
//   - state: true when the client is auto-discovered.
//
// Returns:
//   - string: "auto" or "static".
func FormatClientType[T ~bool](state T) string {
	if state {
		return "auto"
	}

	return "static"
}
