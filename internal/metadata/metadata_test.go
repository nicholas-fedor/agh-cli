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

// TestBuildMetadataReachesVersionInfo verifies that an injected commit and build
// time are appended to the version string and formatted into the version info,
// while the version info keeps the bare version.
//
//nolint:paralleltest // The test sets the package-level build metadata.
func TestBuildMetadataReachesVersionInfo(t *testing.T) {
	setBuildMetadata(t, "abc1234", "2026-01-02T03:04:05Z")

	assert.Equal(t, Version+" (abc1234)", String())

	info := GetInfo()
	assert.Equal(t, Version, info.Version)
	assert.Equal(t, "abc1234", info.CommitSHA)
	assert.Equal(t, "2026-01-02 03:04:05 UTC", info.BuildTime)
}

// setBuildMetadata sets the injected build metadata for one test and restores
// the previous values when it ends.
//
// Parameters:
//   - commitSHA: source revision to inject.
//   - buildTime: RFC3339 build timestamp to inject.
func setBuildMetadata(t *testing.T, commitSHA, buildTime string) {
	t.Helper()

	previousCommitSHA := CommitSHA
	previousBuildTime := BuildTime

	t.Cleanup(func() {
		CommitSHA = previousCommitSHA
		BuildTime = previousBuildTime
	})

	CommitSHA = commitSHA
	BuildTime = buildTime
}
