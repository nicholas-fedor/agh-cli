// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"

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

// configPathKey is the private Viper key holding the resolved configuration
// file for the run. The key is private so no configuration file can shadow it.
const configPathKey = "agh-cli.configPath"

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
// Resolution happens once, here, and both the root command and [ConfigPath]
// consume the result. Letting the configuration search run in two places is what
// let an explicit path behave differently from the default: an explicit missing
// file failed where the default created one.
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
// Parameters:
//   - none.
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
// Parameters:
//   - none.
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

// PublishConfigResolution records the resolved configuration file for the run.
//
// The root command resolves the configuration once in its persistent pre-run and
// publishes the outcome here, so the read and the write always agree on one
// file. The value lives in Viper alongside the rest of the process-global
// configuration state rather than in a second global.
//
// Parameters:
//   - resolution: the outcome produced by [ResolveConfigPath].
//
// Returns:
//   - none.
func PublishConfigResolution(resolution ConfigResolution) {
	viper.Set(configPathKey, resolution.Path)
}

// ConfigPath returns the effective configuration file path.
//
// The root command publishes the resolution before any subcommand runs, so the
// value recorded here is the source of truth. Commands never build a path of
// their own.
//
// The result is always usable as a write destination. When no configuration has
// been published, such as in a test that exercises a command in isolation, the
// per-user path is the destination of the first write. That keeps a first run
// from dropping a configuration into whatever directory it happened to run from.
// A bare [DefaultConfigFileName] is the last resort for a run whose per-user
// configuration root is unavailable.
//
// Returns:
//   - string: the resolved configuration file path.
func ConfigPath() string {
	if path := viper.GetString(configPathKey); path != "" {
		return path
	}

	return perUserWritePath()
}

// LoadConfig loads the configuration file at path.
//
// An absent file yields an empty configuration, so the first write creates it.
// The path is part of the error because an operator must know which file failed.
//
// Instances that cannot be used are reported as a warning on standard error
// rather than failing the load. The load must still succeed, because refusing it
// would leave no way to remove the very instance that is broken.
//
// Parameters:
//   - path: filesystem path of the YAML configuration file.
//
// Returns:
//   - *config.Manager: the loaded configuration, or an empty configuration when
//     the file is absent.
//   - error: a wrapped error when the file cannot be read or parsed.
func LoadConfig(path string) (*config.Manager, error) {
	manager, err := config.Load(path)
	if err != nil {
		return nil, fmt.Errorf("load config %q: %w", path, err)
	}

	warnInvalidInstances(path, manager.ValidationProblems())

	return manager, nil
}

// warnInvalidInstances reports unusable instances on standard error.
//
// The warning names the file and every offending instance so the operator can
// repair the configuration without tracing a failure that would otherwise
// surface only when a command reaches that instance.
//
// Parameters:
//   - path: filesystem path of the loaded configuration file.
//   - problems: the instances that failed validation.
//
// Returns:
//   - none.
func warnInvalidInstances(path string, problems []config.ValidationProblem) {
	if len(problems) == 0 {
		return
	}

	details := make([]string, 0, len(problems))
	for _, problem := range problems {
		details = append(details, fmt.Sprintf("%s: %v", problem.Instance, problem.Err))
	}

	_, _ = fmt.Fprintf(
		os.Stderr,
		"Warning: %s has %d instance(s) that cannot be used: %s\n",
		path,
		len(problems),
		strings.Join(details, "; "),
	)
}

// NewCredentialsCoordinator builds the production credential coordinator.
//
// Construction only assembles dependencies. The configuration file is read but
// never written, and the credential store is not probed, so building a
// coordinator cannot prompt, cannot block on an unavailable keyring, and cannot
// discard a pending change.
//
// The configuration path comes from Viper and the store is the operating system
// credential store, so the command layer depends on neither the configuration
// package nor the credential store adapter.
//
// Returns:
//   - *Credentials: coordinator bound to the resolved configuration file and the
//     operating system credential store.
//   - error: a wrapped error when the configuration file cannot be read.
func NewCredentialsCoordinator() (*Credentials, error) {
	manager, err := LoadConfig(ConfigPath())
	if err != nil {
		return nil, fmt.Errorf("create credential coordinator: %w", err)
	}

	return NewCredentials(NewCredentialStore(), manager), nil
}
