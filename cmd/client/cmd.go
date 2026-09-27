// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/nicholas-fedor/agh-cli/internal/app"
)

// selectionValues stores the selection flag values bound to one client command.
//
// Every command constructor creates its own values so that repeated construction
// never shares flag state between executions.
type selectionValues struct {
	// names holds the --instance flag values.
	names []string
	// all holds the --all flag value.
	all bool
}

// clientMutation executes one app mutation against every selected instance.
type clientMutation func(
	*app.ClientManagement,
	context.Context,
	app.ClientSelection,
	app.ClientMutation,
) ([]app.ClientMutationResult, error)

const (
	// ClientAllFlag names the flag selecting every configured instance.
	clientAllFlag = "all"

	// ClientInstanceFlag names the flag selecting explicit instance names.
	clientInstanceFlag = "instance"

	// ClientUseGlobalFlag names the flag requesting inherited global settings.
	clientUseGlobalFlag = "use-global"

	// ClientFilteringFlag names the flag requesting per-client filtering.
	clientFilteringFlag = "filtering"

	// ClientParentalFlag names the flag requesting per-client parental control.
	clientParentalFlag = "parental"

	// ClientSafebrowsingFlag names the flag requesting per-client safe browsing.
	clientSafebrowsingFlag = "safebrowsing"

	// ClientIDFlag names the flag carrying client identifiers.
	clientIDFlag = "id"
)

// NewCommand creates the client command and registers its subcommands.
//
// Returns:
//   - *cobra.Command: The client command.
func NewCommand() *cobra.Command {
	clientCmd := &cobra.Command{
		Use:   "client",
		Short: "Client operations",
		Long:  `Manage AdGuard Home clients including listing, adding, updating, and deleting.`,
	}

	// Register subcommands.
	clientCmd.AddCommand(
		newClientListCommand(),
		newClientAddCommand(),
		newClientDeleteCommand(),
		newClientUpdateCommand(),
	)

	return clientCmd
}

// newClientMutationCommand creates a named-client mutation command with its own
// flag values.
//
// Parameters:
//   - short: Published one-line description of the subcommand.
//   - use: Published invocation syntax of the subcommand.
//   - run: Run function bound to the values of this command.
//
// Returns:
//   - *cobra.Command: The mutation command with its own flag values.
func newClientMutationCommand(
	short string,
	use string,
	run func(*cobra.Command, []string, *selectionValues) error,
) *cobra.Command {
	values := &selectionValues{}

	command := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cmd, args, values)
		},
	}

	registerClientMutationFlags(command)
	registerClientSelectionFlags(command, values)

	return command
}

// registerClientSelectionFlags registers the instance-selection flags shared by
// every client subcommand.
//
// Each command receives its own flag set bound to its own values, so parsed
// values never outlive the command that owns them.
//
// Parameters:
//   - command: Command receiving its own selection flags.
//   - values: Bound values receiving the parsed selection.
func registerClientSelectionFlags(command *cobra.Command, values *selectionValues) {
	command.Flags().BoolVarP(&values.all, clientAllFlag, "a", false, "target all instances")
	command.Flags().StringSliceVarP(
		&values.names,
		clientInstanceFlag,
		"i",
		[]string{},
		"target instance name(s)",
	)
}

// registerClientMutationFlags registers the mutation flags shared by the add and
// update subcommands.
//
// Parameters:
//   - command: Command receiving its own mutation flags.
func registerClientMutationFlags(command *cobra.Command) {
	command.Flags().BoolP(clientUseGlobalFlag, "g", true, "use global settings")
	command.Flags().BoolP(clientFilteringFlag, "f", false, "enable filtering")
	command.Flags().BoolP(clientParentalFlag, "p", false, "enable parental control")
	command.Flags().BoolP(clientSafebrowsingFlag, "s", false, "enable safebrowsing")
	command.Flags().StringArrayP(
		clientIDFlag,
		"I",
		[]string{},
		"client IDs (IP, CIDR, MAC, or ClientID)",
	)
}

// selection captures active Cobra and Viper selection state.
//
// Returns:
//   - app.ClientSelection: The instance selection taken from flags and configuration.
//   - error: An error when the configured instances cannot be read.
func (values *selectionValues) selection() (app.ClientSelection, error) {
	instances, err := app.InstanceSource()
	if err != nil {
		return app.ClientSelection{}, fmt.Errorf("resolve client instance selection: %w", err)
	}

	return app.ClientSelection{
		Instances:  instances,
		Names:      slices.Clone(values.names),
		All:        values.all,
		ConfigPath: viper.ConfigFileUsed(),
	}, nil
}

// runClientMutation wires flags, app mutation, and success output.
//
// Parameters:
//   - cmd: Cobra command providing output, context, and mutation flag access.
//   - args: Client name argument.
//   - values: Bound flag values selecting the target instances.
//   - mutation: App mutation applied to the assembled client request.
//
// Returns:
//   - error: An error when the mutation flags cannot be parsed or the app
//     mutation fails.
func runClientMutation(
	cmd *cobra.Command,
	args []string,
	values *selectionValues,
	mutation clientMutation,
) error {
	request, err := clientMutationFromFlags(cmd)
	if err != nil {
		return fmt.Errorf("parse client mutation flags: %w", err)
	}

	request.Name = args[0]

	selection, err := values.selection()
	if err != nil {
		return fmt.Errorf("select client instances: %w", err)
	}

	results, operationErr := mutation(
		app.NewClientManagement(),
		cmd.Context(),
		selection,
		request,
	)
	writeClientMutationResults(cmd, results)

	return errors.Join(operationErr)
}

// clientMutationFromFlags reads mutation flags for the app layer.
//
// Parameters:
//   - cmd: Cobra command providing the client mutation flags.
//
// Returns:
//   - app.ClientMutation: The mutation values parsed from the flags.
//   - error: An error when a flag cannot be retrieved.
func clientMutationFromFlags(cmd *cobra.Command) (app.ClientMutation, error) {
	ids, err := cmd.Flags().GetStringArray(clientIDFlag)
	if err != nil {
		return app.ClientMutation{}, fmt.Errorf("parse id flag: %w", err)
	}

	useGlobalSettings, err := cmd.Flags().GetBool(clientUseGlobalFlag)
	if err != nil {
		return app.ClientMutation{}, fmt.Errorf("parse use-global flag: %w", err)
	}

	filteringEnabled, err := cmd.Flags().GetBool(clientFilteringFlag)
	if err != nil {
		return app.ClientMutation{}, fmt.Errorf("parse filtering flag: %w", err)
	}

	parentalEnabled, err := cmd.Flags().GetBool(clientParentalFlag)
	if err != nil {
		return app.ClientMutation{}, fmt.Errorf("parse parental flag: %w", err)
	}

	safebrowsingEnabled, err := cmd.Flags().GetBool(clientSafebrowsingFlag)
	if err != nil {
		return app.ClientMutation{}, fmt.Errorf("parse safebrowsing flag: %w", err)
	}

	return app.ClientMutation{
		IDs:                 ids,
		UseGlobalSettings:   useGlobalSettings,
		FilteringEnabled:    filteringEnabled,
		ParentalEnabled:     parentalEnabled,
		SafebrowsingEnabled: safebrowsingEnabled,
	}, nil
}

// writeClientMutationResults renders successful mutation results in command output.
//
// Parameters:
//   - cmd: Cobra command receiving the rendered messages.
//   - results: Per-instance mutation results to render.
func writeClientMutationResults(cmd *cobra.Command, results []app.ClientMutationResult) {
	for _, result := range results {
		cmd.Printf("[%s] %s\n", result.Instance, result.Message)
	}
}
