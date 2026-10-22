// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/nicholas-fedor/agh-cli/internal/config"
)

// ConfigResolution is the outcome of resolving which configuration file a run
// uses.
//
// The path is always usable as a write destination, so a run with no
// configuration yet still knows where the first write belongs. Exists reports
// whether the file held content worth reading, which is false both when the file
// is absent and when it is blank, because a blank document carries nothing to
// read and is replaced by the first write.
type ConfigResolution struct {
	// Path is the resolved configuration file path.
	Path string
	// Exists reports whether the file existed and held content to read.
	Exists bool
}

// RunConfig is the configuration one run resolved and loaded.
//
// The root command loads it once with [LoadRunConfig] and attaches it to the
// command context with [WithRunConfig]. Every read and every write of the run
// then uses the same loaded file, so they always agree on one file, and a write
// refuses to replace a file that changed after the run read it.
type RunConfig struct {
	// manager is the loaded configuration shared by the whole run.
	manager *config.Manager
}

// runConfigKey is the context key carrying the [RunConfig] of a run.
type runConfigKey struct{}

// DefaultConfigDirName is the agh-cli directory under the per-user
// configuration root.
//
// [os.UserConfigDir] resolves the root, so the directory is
// `$XDG_CONFIG_HOME/agh-cli` or `$HOME/.config/agh-cli` on Unix,
// `~/Library/Application Support/agh-cli` on macOS, and `%AppData%\agh-cli` on
// Windows.
const DefaultConfigDirName = config.DefaultConfigDirName

// DefaultConfigFileName is the configuration file inside
// [DefaultConfigDirName].
//
// The bare name is the last resort for a run whose per-user configuration root
// cannot be resolved, because a relative name is the only location that is
// always available.
const DefaultConfigFileName = config.DefaultConfigFileName

// localConfigDir is the current-directory entry of the default search path.
//
// It lets a project pin its own configuration, and it is the only search entry
// that survives an unresolvable per-user configuration root.
const localConfigDir = "."

// ErrNoRunConfig indicates that an operation ran without a loaded configuration.
var ErrNoRunConfig = errors.New("no configuration loaded for the run")

// UserConfigDir returns the per-user agh-cli configuration directory.
//
// Returns:
//   - string: absolute path of the per-user configuration directory.
//   - error: a wrapped error when the per-user configuration root is
//     unavailable.
func UserConfigDir() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config dir: %w", err)
	}

	return filepath.Join(root, DefaultConfigDirName), nil
}

// UserConfigPath returns the per-user agh-cli configuration file path.
//
// Returns:
//   - string: absolute path of the per-user configuration file.
//   - error: a wrapped error when the per-user configuration root is
//     unavailable.
func UserConfigPath() (string, error) {
	dir, err := UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("resolve user config path: %w", err)
	}

	return filepath.Join(dir, DefaultConfigFileName), nil
}

// ConfigSearchPaths returns the default configuration file locations in priority
// order.
//
// The per-user location comes first, so a configuration created by the quickstart
// keeps applying no matter which directory the command runs from. The current
// directory is the fallback, which lets a project pin its own configuration. An
// unresolvable per-user root drops that entry instead of failing, leaving only
// the current directory.
//
// Each entry is an absolute candidate file, not a directory, so resolution can
// inspect it directly and a reported path is never ambiguous about which
// directory it refers to.
//
// Returns:
//   - []string: ordered absolute candidate configuration file paths.
func ConfigSearchPaths() []string {
	paths := make([]string, 0, 2)

	dir, err := UserConfigDir()
	if err == nil {
		paths = append(paths, filepath.Join(dir, DefaultConfigFileName))
	}

	local, localErr := filepath.Abs(filepath.Join(localConfigDir, DefaultConfigFileName))
	if localErr != nil {
		return paths
	}

	return append(paths, local)
}

// ResolveConfigPath decides which configuration file a run uses.
//
// Resolution happens once, here, and the root command loads the result with
// [LoadRunConfig]. Nothing else searches, because a second search could choose
// another file and make an explicit path behave differently from the default.
//
// An explicit path is used as given. A missing file is not an error, because the
// first write creates it, and a directory or another non-regular file is refused
// because it can never be a configuration document. Without an explicit path the
// default search locations are walked in order and the first file with content
// wins.
//
// Parameters:
//   - explicit: an operator-supplied path, or an empty string to search.
//
// Returns:
//   - ConfigResolution: the path to use and whether it holds content to read.
//   - error: a wrapped error when an explicit path is not a usable file.
func ResolveConfigPath(explicit string) (ConfigResolution, error) {
	if explicit == "" {
		resolution, err := resolveSearchPath()
		if err != nil {
			return ConfigResolution{}, fmt.Errorf("%w", err)
		}

		return resolution, nil
	}

	resolution, err := inspectPath(explicit)
	if err != nil {
		return ConfigResolution{}, fmt.Errorf("%w", err)
	}

	return resolution, nil
}

// resolveSearchPath walks the default search locations in order and takes the
// first file that holds content.
//
// Returns:
//   - ConfigResolution: the first readable configuration, otherwise the per-user
//     write target.
//   - error: a wrapped error when a search location exists but cannot be read.
func resolveSearchPath() (ConfigResolution, error) {
	for _, path := range ConfigSearchPaths() {
		resolution, err := inspectPath(path)
		if err != nil {
			return ConfigResolution{}, fmt.Errorf("%w", err)
		}

		// A location that simply has no file yet is not a failure, so the search
		// continues to the next one.
		if !resolution.Exists {
			continue
		}

		return resolution, nil
	}

	resolution, err := inspectPath(perUserWritePath())
	if err != nil {
		return ConfigResolution{}, fmt.Errorf("%w", err)
	}

	return resolution, nil
}

// inspectPath decides whether one path holds a configuration document.
//
// The returned error already names the path, so it is passed through without
// adding a second mention of the same file.
//
// Parameters:
//   - path: filesystem path to inspect.
//
// Returns:
//   - ConfigResolution: the path with its content state.
//   - error: a wrapped error when the path exists but is not a usable file.
func inspectPath(path string) (ConfigResolution, error) {
	hasContent, err := config.HasContent(path)
	if err != nil {
		return ConfigResolution{}, fmt.Errorf("%w", err)
	}

	return ConfigResolution{Path: path, Exists: hasContent}, nil
}

// perUserWritePath returns the per-user path, or a bare name when the platform
// reports no configuration root.
//
// Returns:
//   - string: the per-user configuration path.
func perUserWritePath() string {
	userPath, err := UserConfigPath()
	if err != nil {
		return DefaultConfigFileName
	}

	return userPath
}

// LoadRunConfig loads the resolved configuration file for the run.
//
// An absent or blank file yields an empty configuration, and the first write
// creates the file. The path is part of the error because an operator must know
// which file failed.
//
// Problems with configured instances are written as warnings rather than failing
// the load, because refusing it would leave no way to remove the very instance
// that is broken. A missing file is reported the same way.
//
// Parameters:
//   - resolution: the outcome produced by [ResolveConfigPath].
//   - warnings: destination of the configuration warnings.
//
// Returns:
//   - RunConfig: the loaded configuration.
//   - error: a wrapped error when the file cannot be read or parsed.
func LoadRunConfig(resolution ConfigResolution, warnings io.Writer) (RunConfig, error) {
	manager, err := config.Load(resolution.Path)
	if err != nil {
		return RunConfig{}, fmt.Errorf("load config %q: %w", resolution.Path, err)
	}

	if !resolution.Exists {
		_, _ = fmt.Fprintf(
			warnings,
			"Warning: no configuration file at %s; one will be created on first write\n",
			resolution.Path,
		)
	}

	warnInstanceProblems(warnings, resolution.Path, manager.ValidationProblems())

	return RunConfig{manager: manager}, nil
}

// WithRunConfig returns a copy of ctx carrying the configuration of the run.
//
// Parameters:
//   - ctx: parent context.
//   - runConfig: the configuration produced by [LoadRunConfig].
//
// Returns:
//   - [context.Context]: a context from which the application layer reads the
//     configuration.
func WithRunConfig(ctx context.Context, runConfig RunConfig) context.Context {
	return context.WithValue(ctx, runConfigKey{}, runConfig)
}

// configFrom returns the configuration of the run carried by ctx.
//
// Parameters:
//   - ctx: context produced by [WithRunConfig].
//
// Returns:
//   - *config.Manager: the loaded configuration of the run.
//   - error: ErrNoRunConfig when ctx carries no configuration.
func configFrom(ctx context.Context) (*config.Manager, error) {
	runConfig, ok := ctx.Value(runConfigKey{}).(RunConfig)
	if !ok || runConfig.manager == nil {
		return nil, ErrNoRunConfig
	}

	return runConfig.manager, nil
}

// warnInstanceProblems reports the problems with configured instances.
//
// The warning names the file and every offending instance so the operator can
// repair the configuration without tracing a failure that would otherwise
// surface only when a command reaches that instance.
//
// Parameters:
//   - warnings: destination of the warning.
//   - path: filesystem path of the loaded configuration file.
//   - problems: the problems found with the configured instances.
func warnInstanceProblems(warnings io.Writer, path string, problems []config.ValidationProblem) {
	if len(problems) == 0 {
		return
	}

	details := make([]string, 0, len(problems))
	for _, problem := range problems {
		details = append(details, fmt.Sprintf("%s: %v", problem.Instance, problem.Err))
	}

	_, _ = fmt.Fprintf(
		warnings,
		"Warning: %s has instance problems: %s\n",
		path,
		strings.Join(details, "; "),
	)
}
