// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// newFilteringStatusCommand creates the filtering status command.
//
// Returns:
//   - *cobra.Command: A fresh status command owning its selection flags.
func newFilteringStatusCommand() *cobra.Command {
	command := &cobra.Command{
		Use:   "status",
		Short: "Get filtering status",
		RunE:  runFilteringStatus,
	}

	registerFilteringSelectionFlags(command)

	return command
}

// runFilteringStatus retrieves filtering status across one or more instances.
//
// Parameters:
//   - cmd: Cobra command context.
//   - args: Unused positional arguments.
//
// Returns:
//   - error: An error when flag parsing, a per-instance request, or an output
//     operation fails.
func runFilteringStatus(cmd *cobra.Command, _ []string) error {
	selection, err := currentFilteringSelection(cmd)
	if err != nil {
		return fmt.Errorf("parse filtering flags: %w", err)
	}

	results, operationErr := app.NewFilteringManagement().Status(
		cmd.Context(),
		selection,
	)
	outputErr := writeFilteringStatuses(cmd, results)

	err = errors.Join(operationErr, outputErr)
	if err != nil {
		return fmt.Errorf("get filtering status: %w", err)
	}

	return nil
}

// writeFilteringStatuses renders every successful filtering status result.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered status tables.
//   - results: Per-instance filtering status results to render.
//
// Returns:
//   - error: Joined errors from every failed instance table.
func writeFilteringStatuses(cmd *cobra.Command, results []app.FilteringStatusResult) error {
	errs := make([]error, 0, len(results))

	for _, result := range results {
		err := writeFilteringStatus(cmd, result)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// writeFilteringStatus renders one filtering status result.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered status table.
//   - result: One per-instance filtering status result.
//
// Returns:
//   - error: An error when the status table cannot be written.
func writeFilteringStatus(cmd *cobra.Command, result app.FilteringStatusResult) error {
	writer := cmd.OutOrStdout()
	err := writeFilteringStatusHeader(writer, result)
	if err != nil {
		return fmt.Errorf("write instance %q filtering status header: %w", result.Instance, err)
	}

	tableWriter := output.NewTableWriter("INSTANCE", "NAME", "ENABLED", "RULES", "URL")
	writeFilteringSubscriptions(tableWriter, result.Instance, result.Filters)
	writeFilteringSubscriptions(tableWriter, result.Instance, result.WhitelistFilters)

	_, err = tableWriter.WriteTo(writer)
	if err != nil {
		return fmt.Errorf("write instance %q filtering status: %w", result.Instance, err)
	}

	return nil
}

// writeFilteringStatusHeader renders the optional instance separator and header.
//
// Parameters:
//   - writer: Destination for the separator and instance header.
//   - result: One per-instance filtering status result.
//
// Returns:
//   - error: An error when the separator or header cannot be written.
func writeFilteringStatusHeader(
	writer io.Writer,
	result app.FilteringStatusResult,
) error {
	var err error

	if result.Index > 0 && result.InstanceCount > 1 {
		_, err = fmt.Fprintln(writer)
		if err != nil {
			return fmt.Errorf("write instance separator: %w", err)
		}
	}

	if result.InstanceCount <= 1 {
		return nil
	}

	_, err = fmt.Fprintf(writer, "Instance: %s\n", result.Instance)
	if err != nil {
		return fmt.Errorf("write instance %q header: %w", result.Instance, err)
	}

	return nil
}

// writeFilteringSubscriptions appends one optional subscription list to a table.
//
// Parameters:
//   - tableWriter: Table receiving one row per subscription.
//   - instance: Instance name repeated on every appended row.
//   - subscriptions: Optional subscriptions, skipped when absent.
func writeFilteringSubscriptions(
	tableWriter *output.TableWriter,
	instance string,
	subscriptions *[]app.FilteringSubscription,
) {
	if subscriptions == nil {
		return
	}

	for _, subscription := range *subscriptions {
		tableWriter.Row(
			instance,
			subscription.Name,
			output.FormatEnabled(subscription.Enabled),
			strconv.FormatUint(uint64(subscription.RulesCount), 10),
			subscription.URL,
		)
	}
}
