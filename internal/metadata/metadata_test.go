// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package metadata

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_initVersion verifies initVersion does not panic.
func Test_initVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
	}{
		{
			name: "initializes version without panic",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			initVersion()
		})
	}
}

// TestString verifies String returns a non-empty version string.
func TestString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
	}{
		{
			name: "returns non-empty string",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := String()
			assert.NotEmpty(t, got)
		})
	}
}

// TestGetGoVersion verifies GetGoVersion returns a non-empty Go version string.
func TestGetGoVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
	}{
		{
			name: "returns go version or unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := GetGoVersion()
			assert.NotEmpty(t, got)
		})
	}
}

// TestConvertToLocal verifies UTC time strings are converted to local time format.
func TestConvertToLocal(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		utcStr string
		want   string
	}{
		{
			name:   "empty string returns empty",
			utcStr: "",
			want:   "",
		},
		{
			name:   "valid UTC time converts",
			utcStr: "2026-01-01T00:00:00Z",
			want:   "2026-01-01 00:00:00 UTC",
		},
		{
			name:   "invalid time returns original",
			utcStr: "not-a-time",
			want:   "not-a-time",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := ConvertToLocal(tt.utcStr)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestGetInfo verifies GetInfo returns populated version metadata.
func TestGetInfo(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
	}{
		{
			name: "returns populated version info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := GetInfo()
			assert.Equal(t, Name, got.Name)
			assert.Equal(t, Version, got.Version)
			assert.NotEmpty(t, got.GoVersion)
			assert.NotEmpty(t, got.OS)
			assert.NotEmpty(t, got.Arch)
		})
	}
}
