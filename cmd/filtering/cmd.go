// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

const (
	// FilteringAllFlag names the flag selecting every configured instance.
	filteringAllFlag = "all"

	// FilteringInstanceFlag names the flag selecting explicit instance names.
	filteringInstanceFlag = "instance"
)

// NewCommand creates the filtering command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The filtering command.
func NewCommand() *cobra.Command {
	filteringCmd := &cobra.Command{
		Use:   "filtering",
		Short: "Filtering operations",
		Long:  `Manage AdGuard Home filtering configuration, rules, and filter URLs.`,
	}

	// Register subcommands.
	filteringCmd.AddCommand(
		newFilteringStatusCommand(),
		newFilteringConfigCommand(),
		newFilteringAddURLCommand(),
		newFilteringRemoveURLCommand(),
	)

	return filteringCmd
}

// registerFilteringSelectionFlags registers the instance-selection flags shared by
// every filtering subcommand.
//
// Each command receives its own flag set, so parsed values never outlive the
// command that owns them.
//
// Parameters:
//   - command: Command receiving its own selection flags.
func registerFilteringSelectionFlags(command *cobra.Command) {
	command.Flags().BoolP(filteringAllFlag, "a", false, "target all instances")
	command.Flags().StringSliceP(
		filteringInstanceFlag,
		"i",
		[]string{},
		"target instance name(s)",
	)
}

// currentFilteringSelection captures the active Cobra and Viper selection state.
//
// Parameters:
//   - cmd: Cobra command providing the instance-selection flags.
//
// Returns:
//   - app.FilteringSelection: The instance selection taken from flags and configuration.
//   - error: An error when a selection flag cannot be retrieved or the configured
//     instances cannot be read.
func currentFilteringSelection(cmd *cobra.Command) (app.FilteringSelection, error) {
	names, err := cmd.Flags().GetStringSlice(filteringInstanceFlag)
	if err != nil {
		return app.FilteringSelection{}, fmt.Errorf("parse instance flag: %w", err)
	}

	all, err := cmd.Flags().GetBool(filteringAllFlag)
	if err != nil {
		return app.FilteringSelection{}, fmt.Errorf("parse all flag: %w", err)
	}

	instances, err := app.InstanceSource()
	if err != nil {
		return app.FilteringSelection{}, fmt.Errorf(
			"resolve filtering instance selection: %w",
			err,
		)
	}

	return app.FilteringSelection{
		Instances:  instances,
		Names:      names,
		ConfigPath: viper.ConfigFileUsed(),
		All:        all,
	}, nil
}

// filteringURLFromFlags preserves the explicit whitelist flag value.
//
// Parameters:
//   - cmd: Cobra command providing the whitelist flag.
//
// Returns:
//   - bool: The explicit whitelist flag value.
//   - error: An error when the flag cannot be retrieved.
func filteringURLFromFlags(cmd *cobra.Command) (bool, error) {
	whitelist, err := cmd.Flags().GetBool("whitelist")
	if err != nil {
		return false, fmt.Errorf("parse whitelist flag: %w", err)
	}

	return whitelist, nil
}

// writeFilteringMutationResults renders every successful mutation result.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered messages.
//   - results: Per-instance mutation results to render.
//
// Returns:
//   - error: Joined errors from every failed message write.
func writeFilteringMutationResults(
	cmd *cobra.Command,
	results []app.FilteringMutationResult,
) error {
	writer := cmd.OutOrStdout()
	errs := make([]error, 0, len(results))

	for _, result := range results {
		_, err := fmt.Fprintf(writer, "[%s] %s\n", result.Instance, result.Message)
		if err != nil {
			errs = append(errs, fmt.Errorf("write instance %q result: %w", result.Instance, err))
		}
	}

	return errors.Join(errs...)
}
