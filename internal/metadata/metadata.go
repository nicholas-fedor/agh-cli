// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package metadata

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"time"
)

// VersionInfo contains the application version and build environment metadata.
type VersionInfo struct {
	// Name is the application name.
	Name string `json:"name"`
	// Version is the application version without an appended commit suffix.
	Version string `json:"version"`
	// CommitSHA is the source revision injected at build time, or empty when absent.
	CommitSHA string `json:"commitSha,omitempty"`
	// BuildTime is the build timestamp formatted for display, or empty when absent.
	BuildTime string `json:"buildTime,omitempty"`
	// GoVersion is the Go toolchain version used for the build, or "unknown".
	GoVersion string `json:"goVersion,omitempty"`
	// OS is the operating system targeted by the build.
	OS string `json:"os"`
	// Arch is the CPU architecture targeted by the build.
	Arch string `json:"arch"`
}

const (
	// Name is the application name.
	Name = "agh-cli"
	// DefaultVersion is the version reported when neither the build nor the Go
	// build information supplies one.
	DefaultVersion = "dev"
	// Optional metadata uses emptyString as its absent-value sentinel.
	emptyString = ""
	// Go records develModuleVersion as the main module version when it builds a
	// source tree that has no version.
	develModuleVersion = "(devel)"
)

var (
	// Version is the application version injected at build time. It stays
	// DefaultVersion when the build injects none, and the reported version then
	// comes from the Go build information.
	Version = DefaultVersion
	// CommitSHA is the optional source revision injected at build time.
	CommitSHA = ""
	// BuildTime is the optional RFC3339 build timestamp injected at build time.
	BuildTime = ""
)

// resolveVersion returns the version the application reports.
//
// A version injected at build time always wins. Without one, the main module
// version from the Go build information is used, such as the one go install
// records for a tagged module. DefaultVersion is the last resort, for builds
// whose build information has no version.
//
// Parameters:
//   - injected: the version injected at build time, or DefaultVersion or an
//     empty string when the build injected none.
//   - readBuildInfo: reads the Go build information, such as [debug.ReadBuildInfo].
//
// Returns:
//   - string: the injected version, the module version, or DefaultVersion.
func resolveVersion(injected string, readBuildInfo func() (*debug.BuildInfo, bool)) string {
	if injected != DefaultVersion && injected != emptyString {
		return injected
	}

	info, ok := readBuildInfo()
	if !ok || info.Main.Version == emptyString || info.Main.Version == develModuleVersion {
		return DefaultVersion
	}

	return info.Main.Version
}

// String returns the application version and appends CommitSHA when present.
//
// Returns:
//   - string: application version, optionally followed by the commit SHA.
func String() string {
	version := resolveVersion(Version, debug.ReadBuildInfo)

	if CommitSHA != emptyString {
		return fmt.Sprintf("%s (%s)", version, CommitSHA)
	}

	return version
}

// GetGoVersion returns the Go toolchain version used for the build.
//
// Returns:
//   - string: toolchain version from build information, or "unknown" when unavailable.
func GetGoVersion() string {
	if info, ok := debug.ReadBuildInfo(); ok && info.GoVersion != emptyString {
		return info.GoVersion
	}

	return "unknown"
}

// ConvertToLocal formats an RFC3339 build timestamp with the fixed
// "2006-01-02 15:04:05 UTC" display layout.
//
// Empty input remains empty, and invalid input is returned unchanged.
//
// Parameters:
//   - utcStr: build timestamp in RFC3339 format.
//
// Returns:
//   - string: formatted timestamp, an empty string for empty input, or the original
//     value when parsing fails.
func ConvertToLocal(utcStr string) string {
	if utcStr == emptyString {
		return emptyString
	}

	utcTime, err := time.Parse(time.RFC3339, utcStr)
	if err != nil {
		return utcStr
	}

	return utcTime.Format("2006-01-02 15:04:05 UTC")
}

// GetInfo returns the current application and build metadata without appending
// CommitSHA to Version.
//
// Returns:
//   - VersionInfo: application version and build environment metadata.
func GetInfo() VersionInfo {
	commitSHA := ""
	if CommitSHA != emptyString {
		commitSHA = CommitSHA
	}

	buildTime := ""
	if BuildTime != emptyString {
		buildTime = ConvertToLocal(BuildTime)
	}

	info := VersionInfo{
		Name:      Name,
		Version:   resolveVersion(Version, debug.ReadBuildInfo),
		CommitSHA: commitSHA,
		BuildTime: buildTime,
		GoVersion: GetGoVersion(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}

	return info
}
