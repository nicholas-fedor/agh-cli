// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"errors"
	"fmt"
	"io"
	"strconv"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/filtering"
)

// WriteFilteringStatuses writes one subscription table per instance that
// answered.
//
// Parameters:
//   - writer: destination for the tables.
//   - results: per-instance filtering status results in configuration order.
//
// Returns:
//   - error: joined errors from every table that could not be written.
func WriteFilteringStatuses(writer io.Writer, results []app.FilteringStatusResult) error {
	errs := make([]error, 0, len(results))

	for position, result := range results {
		err := writeFilteringStatus(writer, position, result)
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

// writeFilteringStatus writes the subscription table of one instance.
//
// Parameters:
//   - writer: destination for the table.
//   - position: zero-based position of the table among the written tables.
//   - result: filtering status of one instance.
//
// Returns:
//   - error: a wrapped error when the heading or the table cannot be written.
func writeFilteringStatus(writer io.Writer, position int, result app.FilteringStatusResult) error {
	err := writeInstanceHeader(writer, position, result.InstanceCount, result.Instance)
	if err != nil {
		return fmt.Errorf("write instance %q filtering status header: %w", result.Instance, err)
	}

	tableWriter := NewTableWriter("INSTANCE", "NAME", "ENABLED", "RULES", "URL")
	addFilteringSubscriptions(tableWriter, result.Instance, result.Filters)
	addFilteringSubscriptions(tableWriter, result.Instance, result.WhitelistFilters)

	_, err = tableWriter.WriteTo(writer)
	if err != nil {
		return fmt.Errorf("write instance %q filtering status: %w", result.Instance, err)
	}

	return nil
}

// addFilteringSubscriptions appends one optional subscription list to a table.
//
// Parameters:
//   - tableWriter: table receiving one row per subscription.
//   - instance: instance name repeated on every appended row.
//   - subscriptions: optional subscriptions, skipped when absent.
func addFilteringSubscriptions(
	tableWriter *TableWriter,
	instance string,
	subscriptions *[]filtering.Subscription,
) {
	if subscriptions == nil {
		return
	}

	for _, subscription := range *subscriptions {
		tableWriter.Row(
			instance,
			subscription.Name,
			FormatEnabled(subscription.Enabled),
			strconv.FormatUint(uint64(subscription.RulesCount), 10),
			subscription.URL,
		)
	}
}
