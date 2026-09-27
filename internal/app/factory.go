// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/nicholas-fedor/agh-cli/internal/config"
	"github.com/nicholas-fedor/agh-cli/internal/credentials"
)

// DefaultConfigFileName is the configuration file used when Viper resolved no
// explicit path.
//
// The root command registers `./` and `~/.config/agh-cli` as Viper search paths,
// so a resolved path is the normal case. The fallback keeps a command that runs
// without the root persistent pre-run working against the conventional file in
// the current directory.
const DefaultConfigFileName = "config.yaml"

// ConfigPath returns the effective configuration file path.
//
// The root command reads the configuration file into Viper before any
// subcommand runs, so the resolved Viper path is the source of truth. Commands
// never build a path of their own.
//
// Returns:
//   - string: the resolved configuration file path, or
//     [DefaultConfigFileName] when Viper resolved none.
func ConfigPath() string {
	path := viper.ConfigFileUsed()
	if path == "" {
		return DefaultConfigFileName
	}

	return path
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
