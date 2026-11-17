// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package metadata

import (
	"runtime/debug"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Test_resolveVersion verifies that an injected version wins over the Go build
// information, which in turn wins over the default. A build from a source tree
// records an empty or "(devel)" module version, which must not replace the
// injected one or be reported.
func Test_resolveVersion(t *testing.T) {
	t.Parallel()

	tests := []struct {
		readBuildInfo func() (*debug.BuildInfo, bool)
		name          string
		injected      string
		want          string
	}{
		{
			name:          "injected version wins over the module version",
			injected:      "v1.2.3-4-gabc1234",
			readBuildInfo: buildInfoWithModuleVersion("v1.2.3"),
			want:          "v1.2.3-4-gabc1234",
		},
		{
			name:          "injected version wins over an empty module version",
			injected:      "v1.2.3",
			readBuildInfo: buildInfoWithModuleVersion(""),
			want:          "v1.2.3",
		},
		{
			name:          "injected version wins without build information",
			injected:      "v1.2.3",
			readBuildInfo: noBuildInfo,
			want:          "v1.2.3",
		},
		{
			name:          "module version stands in for the default",
			injected:      DefaultVersion,
			readBuildInfo: buildInfoWithModuleVersion("v1.2.3"),
			want:          "v1.2.3",
		},
		{
			name:          "module version stands in for an empty injection",
			injected:      "",
			readBuildInfo: buildInfoWithModuleVersion("v1.2.3"),
			want:          "v1.2.3",
		},
		{
			name:          "devel module version reports the default",
			injected:      DefaultVersion,
			readBuildInfo: buildInfoWithModuleVersion("(devel)"),
			want:          DefaultVersion,
		},
		{
			name:          "empty module version reports the default",
			injected:      DefaultVersion,
			readBuildInfo: buildInfoWithModuleVersion(""),
			want:          DefaultVersion,
		},
		{
			name:          "missing build information reports the default",
			injected:      DefaultVersion,
			readBuildInfo: noBuildInfo,
			want:          DefaultVersion,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			assert.Equal(t, tt.want, resolveVersion(tt.injected, tt.readBuildInfo))
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
			assert.NotEmpty(t, got.Version)
			assert.NotEmpty(t, got.GoVersion)
			assert.NotEmpty(t, got.OS)
			assert.NotEmpty(t, got.Arch)
		})
	}
}

// TestBuildMetadataReachesVersionInfo verifies that an injected version, commit,
// and build time reach the version string and the version info, while the
// version info keeps the bare version.
//
//nolint:paralleltest // The test sets the package-level build metadata.
func TestBuildMetadataReachesVersionInfo(t *testing.T) {
	setBuildMetadata(t, "v1.2.3-4-gabc1234", "abc1234", "2026-01-02T03:04:05Z")

	assert.Equal(t, "v1.2.3-4-gabc1234 (abc1234)", String())

	info := GetInfo()
	assert.Equal(t, "v1.2.3-4-gabc1234", info.Version)
	assert.Equal(t, "abc1234", info.CommitSHA)
	assert.Equal(t, "2026-01-02 03:04:05 UTC", info.BuildTime)
}

// setBuildMetadata sets the injected build metadata for one test and restores
// the previous values when it ends.
//
// Parameters:
//   - version: application version to inject.
//   - commitSHA: source revision to inject.
//   - buildTime: RFC3339 build timestamp to inject.
func setBuildMetadata(t *testing.T, version, commitSHA, buildTime string) {
	t.Helper()

	previousVersion := Version
	previousCommitSHA := CommitSHA
	previousBuildTime := BuildTime

	t.Cleanup(func() {
		Version = previousVersion
		CommitSHA = previousCommitSHA
		BuildTime = previousBuildTime
	})

	Version = version
	CommitSHA = commitSHA
	BuildTime = buildTime
}

// buildInfoWithModuleVersion returns a build information reader whose main
// module has version.
//
// Parameters:
//   - version: main module version the reader reports.
//
// Returns:
//   - func() (*debug.BuildInfo, bool): a reader that always succeeds.
func buildInfoWithModuleVersion(version string) func() (*debug.BuildInfo, bool) {
	return func() (*debug.BuildInfo, bool) {
		return &debug.BuildInfo{
			GoVersion: "go1.27.1",
			Path:      "github.com/nicholas-fedor/agh-cli",
			Main: debug.Module{
				Path:    "github.com/nicholas-fedor/agh-cli",
				Version: version,
				Sum:     "",
				Replace: nil,
			},
			Deps:     nil,
			Settings: nil,
		}, true
	}
}

// noBuildInfo is a build information reader for a binary built without module
// support.
//
// Returns:
//   - *[debug.BuildInfo]: always nil.
//   - bool: always false.
func noBuildInfo() (*debug.BuildInfo, bool) {
	return nil, false
}
