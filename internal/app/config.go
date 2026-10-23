// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/nicholas-fedor/agh-cli/internal/config"
)

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

// ErrNoRunConfig indicates that an operation ran without a loaded configuration.
var ErrNoRunConfig = errors.New("no configuration loaded for the run")

// ResolveConfigPath decides which configuration file a run uses.
//
// It forwards to [config.Resolve], so the command layer resolves the file
// without naming the configuration package.
//
// Parameters:
//   - explicit: an operator-supplied path, or an empty string to search.
//
// Returns:
//   - config.Resolution: the path to use and whether it holds content to read.
//   - error: a wrapped error when an explicit path is not a usable file.
func ResolveConfigPath(explicit string) (config.Resolution, error) {
	resolution, err := config.Resolve(explicit)
	if err != nil {
		return config.Resolution{}, fmt.Errorf("%w", err)
	}

	return resolution, nil
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
func LoadRunConfig(resolution config.Resolution, warnings io.Writer) (RunConfig, error) {
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
