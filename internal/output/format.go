// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"fmt"
	"reflect"
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

// FormatRewriteValue formats rewrite values used by existing command output.
//
// New rendering code should construct a RewriteValue and call FormatRewrite.
// The legacy shape is adapted without coupling this package to its owner.
//
// Parameters:
//   - value: neutral rewrite value or legacy rewrite entry.
//
// Returns:
//   - string: formatted display string, or "-" when value is nil.
func FormatRewriteValue(value any) string {
	switch rewriteValue := value.(type) {
	case nil:
		return "-"
	case RewriteValue:
		return FormatRewrite(rewriteValue)
	case *RewriteValue:
		if rewriteValue == nil {
			return "-"
		}

		return FormatRewrite(*rewriteValue)
	default:
		legacyValue, ok := rewriteValueFromLegacy(value)
		if !ok {
			return "-"
		}

		return FormatRewrite(legacyValue)
	}
}

// rewriteValueFromLegacy adapts a legacy rewrite entry through its neutral
// field representation.
//
// Parameters:
//   - value: legacy rewrite entry.
//
// Returns:
//   - RewriteValue: neutral rewrite value.
//   - bool: false when value is nil.
func rewriteValueFromLegacy(value any) (RewriteValue, bool) {
	reflected := reflect.Indirect(reflect.ValueOf(value))
	if !reflected.IsValid() {
		return RewriteValue{Answer: "", Enabled: false}, false
	}

	if reflected.Kind() != reflect.Struct {
		panic("rewrite value must be a struct or struct pointer")
	}

	answer := reflected.FieldByName("Answer")
	enabled := reflected.FieldByName("Enabled")
	if !answer.IsValid() || answer.Kind() != reflect.String ||
		!enabled.IsValid() || enabled.Kind() != reflect.Bool {

		panic("rewrite value must expose string Answer and bool Enabled fields")
	}

	return RewriteValue{Answer: answer.String(), Enabled: enabled.Bool()}, true
}
