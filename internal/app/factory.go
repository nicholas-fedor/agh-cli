// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/nicholas-fedor/agh-cli/internal/config"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

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

// ConfigSearchPaths returns the default configuration search paths in priority
// order.
//
// The per-user directory is searched before the current directory, so the
// configuration the quickstart creates keeps applying no matter which directory
// the command runs from. An unresolvable per-user root drops that entry instead
// of failing, leaving the current directory as the only search path.
//
// Returns:
//   - []string: ordered search paths for a configuration file.
func ConfigSearchPaths() []string {
	paths := make([]string, 0, 2)

	dir, err := UserConfigDir()
	if err == nil {
		paths = append(paths, dir)
	}

	return append(paths, localConfigDir)
}

// ConfigPath returns the effective configuration file path.
//
// The root command reads the configuration file into Viper before any
// subcommand runs, so the resolved Viper path is the source of truth. Commands
// never build a path of their own.
//
// Viper resolves nothing exactly when no configuration file exists yet, so the
// per-user path is the destination of the first write. That keeps a first run
// from dropping a configuration into whatever directory it happened to run
// from. A bare [DefaultConfigFileName] is the last resort for a run whose
// per-user configuration root is unavailable.
//
// Returns:
//   - string: the resolved configuration file path, otherwise the per-user path
//     when Viper resolved none, otherwise [DefaultConfigFileName].
func ConfigPath() string {
	path := viper.ConfigFileUsed()
	if path != "" {
		return path
	}

	userPath, err := UserConfigPath()
	if err != nil {
		return DefaultConfigFileName
	}

	return userPath
}

// LoadConfig loads the configuration file at path.
//
// An absent file yields an empty configuration, so the first write creates it.
// The path is part of the error because an operator must know which file failed.
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

	return manager, nil
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

	return NewCredentials(credentials.NewSystemStore(), manager), nil
}
