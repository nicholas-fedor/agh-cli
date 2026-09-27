// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package metadata

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
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
	// DefaultVersion is used when no released version is available.
	DefaultVersion = "dev"
	// Optional metadata uses emptyString as its absent-value sentinel.
	emptyString = ""
)

var (
	// Version is the application version before CommitSHA is appended.
	Version = DefaultVersion
	// CommitSHA is the optional source revision injected at build time.
	CommitSHA = ""
	// BuildTime is the optional RFC3339 build timestamp injected at build time.
	BuildTime = ""

	// The versionOnce guard limits version initialization to one execution.
	versionOnce sync.Once
)

// initVersion initializes Version from embedded build information when a
// non-development version is available.
func initVersion() {
	if info, ok := debug.ReadBuildInfo(); ok && info.Main.Version != "(devel)" {
		Version = info.Main.Version
	}
}

// String returns the application version and appends CommitSHA when present.
//
// Returns:
//   - string: application version, optionally followed by the commit SHA.
func String() string {
	versionOnce.Do(initVersion)

	if CommitSHA != emptyString {
		return fmt.Sprintf("%s (%s)", Version, CommitSHA)
	}

	return Version
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
		Version:   Version,
		CommitSHA: commitSHA,
		BuildTime: buildTime,
		GoVersion: GetGoVersion(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}

	return info
}
