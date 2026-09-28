// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nicholas-fedor/agh-cli/cmd/rewrite/settings"
	"github.com/nicholas-fedor/agh-cli/cmd/rewrite/wildcard"
	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/output"
)

// rewriteMutation executes one app mutation from command-supplied values.
type rewriteMutation func(
	*app.RewriteManagement,
	context.Context,
	app.RewriteSelection,
	app.RewriteRuleInput,
) ([]app.RewriteMutationResult, error)

// flagValues stores the flag values bound to one rewrite command.
//
// Every command constructor creates its own values so that repeated
// construction never shares flag state between executions.
type flagValues struct {
	// names holds the --instance flag values.
	names []string
	// all holds the --all flag value.
	all bool
	// sortColumn holds the --sort flag value.
	sortColumn string
	// enabled holds the --enabled flag value.
	enabled bool
	// answer holds the --answer flag value.
	answer string
	// file holds the --file flag value.
	file string
}

// answerSortColumn identifies sorting by the rewrite answer column.
const answerSortColumn = "answer"

// NewCommand creates the rewrite command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The rewrite command.
func NewCommand() *cobra.Command {
	rewriteCmd := &cobra.Command{
		Use:   "rewrite",
		Short: "DNS rewrite rule operations",
		Long: `Create, read, update, and delete DNS rewrite rules on one or more
AdGuard Home instances.`,
	}

	// Register subcommands.
	rewriteCmd.AddCommand(
		newRewriteListCommand(),
		newRewriteAddCommand(),
		newRewriteDeleteCommand(),
		newRewriteUpdateCommand(),
		newRewriteDiffCommand(),
		settings.NewCommand(),
		wildcard.NewCommand(),
	)

	return rewriteCmd
}

// selection captures active Cobra and Viper selection state.
//
// Returns:
//   - app.RewriteSelection: The instance selection taken from flags and configuration.
//   - error: An error when the configured instances cannot be read.
func (values *flagValues) selection() (app.RewriteSelection, error) {
	instances, err := app.InstanceSource()
	if err != nil {
		return app.RewriteSelection{}, fmt.Errorf("resolve rewrite instance selection: %w", err)
	}

	return app.RewriteSelection{
		Instances:  instances,
		Names:      slices.Clone(values.names),
		ConfigPath: viper.ConfigFileUsed(),
		All:        values.all,
	}, nil
}

// newRewriteRuleCommand creates a rewrite rule mutation command and returns it
// with the fresh flag values its own file binds the command flags to.
//
// The command body runs the supplied mutation for the supplied domain and
// answer arguments, wrapping every failure with the action name.
//
// Parameters:
//   - use: Command usage line.
//   - short: Command short description.
//   - action: Command action name prefixed to wrapped failures.
//   - mutation: App mutation invoked with the assembled rule request.
//
// Returns:
//   - *cobra.Command: The created command awaiting flag registration.
//   - *flagValues: The fresh values the command flags bind to.
func newRewriteRuleCommand(
	use string,
	short string,
	action string,
	mutation rewriteMutation,
) (*cobra.Command, *flagValues) {
	values := &flagValues{}

	command := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runRewriteRuleMutation(cmd, values, args[0], args[1], mutation)
			if err != nil {
				return fmt.Errorf("%s: %w", action, err)
			}

			return nil
		},
	}

	return command, values
}

// runRewriteRuleMutation wires flags, app mutation, and success output.
//
// Parameters:
//   - cmd: Cobra command providing output and context.
//   - values: Bound flag values selecting instances and rule state.
//   - domain: Domain the mutation targets.
//   - answer: Answer the mutation writes for the domain.
//   - mutation: App mutation invoked with the assembled rule request.
//
// Returns:
//   - error: An error when the app mutation fails or the success output cannot
//     be written.
func runRewriteRuleMutation(
	cmd *cobra.Command,
	values *flagValues,
	domain string,
	answer string,
	mutation rewriteMutation,
) error {
	selection, err := values.selection()
	if err != nil {
		return fmt.Errorf("select rewrite instances: %w", err)
	}

	results, mutationErr := mutation(
		app.NewRewriteManagement(),
		cmd.Context(),
		selection,
		app.RewriteRuleInput{
			Domain:  domain,
			Answer:  answer,
			Enabled: values.enabled,
		},
	)

	outputErr := writeRewriteMutationResults(cmd, results)

	mutationErr = errors.Join(mutationErr, outputErr)

	return mutationErr
}

// writeRewriteMutationResults renders every successful mutation result.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered messages.
//   - results: Per-instance mutation results to render.
//
// Returns:
//   - error: Joined errors from every failed message write.
func writeRewriteMutationResults(
	cmd *cobra.Command,
	results []app.RewriteMutationResult,
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

// applyRewriteSort configures domain- or answer-oriented table sorting.
//
// Parameters:
//   - tableWriter: Table whose sort column is configured.
//   - sortColumn: Selected sort column, or an empty value for the default.
//   - defaultColumn: Header used when no sort column is selected.
func applyRewriteSort(
	tableWriter *output.TableWriter,
	sortColumn string,
	defaultColumn string,
) {
	column := sortColumn
	if column == "" {
		column = defaultColumn
	}

	if column == answerSortColumn {
		tableWriter.SortByHeader(column, output.AnswerLess)

		return
	}

	tableWriter.SortByHeader(column, output.DomainLess)
}
