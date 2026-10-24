// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package flags

import (
	"errors"
	"fmt"

	"github.com/spf13/pflag"

	"github.com/nicholas-fedor/agh-cli/internal/output"
	"github.com/nicholas-fedor/agh-cli/internal/rewrite"
)

// RewriteRuleFlags stores the flags of the rewrite add and update commands.
type RewriteRuleFlags struct {
	// InstanceSelection stores the instance-selection flags.
	InstanceSelection

	// Enabled holds the --enabled flag value.
	Enabled bool
}

// RewriteDeleteFlags stores the flags of the rewrite delete command.
type RewriteDeleteFlags struct {
	// InstanceSelection stores the instance-selection flags.
	InstanceSelection

	// Answer holds the --answer flag value.
	Answer string
	// Enabled holds the --enabled flag value.
	Enabled bool
}

// RewriteListFlags stores the flags of the rewrite list command.
type RewriteListFlags struct {
	// InstanceSelection stores the instance-selection flags.
	InstanceSelection

	// Sort holds the --sort flag value.
	Sort string
}

// RewriteDiffFlags stores the flags of the rewrite diff command.
type RewriteDiffFlags struct {
	// InstanceSelection stores the instance-selection flags.
	InstanceSelection

	// File holds the --file flag value.
	File string
	// Sort holds the --sort flag value.
	Sort string
}

// ErrAnswerRequired reports a rewrite deletion without its --answer flag.
var ErrAnswerRequired = errors.New("--answer is required when deleting a rewrite rule")

// Bind registers the rule state and instance-selection flags and binds their
// values to the receiver.
//
// Parameters:
//   - flags: flag set that receives the rule flags.
func (f *RewriteRuleFlags) Bind(flags *pflag.FlagSet) {
	flags.BoolVarP(&f.Enabled, "enabled", "e", true, "enable rule")
	f.InstanceSelection.Bind(flags)
}

// Request returns the rewrite rule the arguments and flags describe.
//
// Parameters:
//   - domain: rewritten domain.
//   - answer: answer the domain resolves to.
//
// Returns:
//   - [rewrite.RuleRequest]: the rule sent to every selected instance.
func (f *RewriteRuleFlags) Request(domain, answer string) rewrite.RuleRequest {
	return rewrite.RuleRequest{Domain: domain, Answer: answer, Enabled: f.Enabled}
}

// Bind registers the answer, rule state, and instance-selection flags and binds
// their values to the receiver.
//
// Parameters:
//   - flags: flag set that receives the delete flags.
func (f *RewriteDeleteFlags) Bind(flags *pflag.FlagSet) {
	flags.StringVarP(&f.Answer, "answer", "A", "", "answer/IP to delete")
	flags.BoolVarP(&f.Enabled, "enabled", "e", true, "rule enabled state")
	f.InstanceSelection.Bind(flags)
}

// Request returns the rewrite rule the argument and flags identify.
//
// Parameters:
//   - domain: rewritten domain.
//
// Returns:
//   - [rewrite.RuleRequest]: the rule removed from every selected instance.
func (f *RewriteDeleteFlags) Request(domain string) rewrite.RuleRequest {
	return rewrite.RuleRequest{Domain: domain, Answer: f.Answer, Enabled: f.Enabled}
}

// Validate refuses a deletion that names no answer.
//
// Returns:
//   - error: [ErrAnswerRequired] when --answer is empty.
func (f *RewriteDeleteFlags) Validate() error {
	if f.Answer == "" {
		return ErrAnswerRequired
	}

	return nil
}

// Bind registers the sort and instance-selection flags and binds their values to
// the receiver.
//
// Parameters:
//   - flags: flag set that receives the list flags.
func (f *RewriteListFlags) Bind(flags *pflag.FlagSet) {
	f.InstanceSelection.Bind(flags)
	flags.StringVarP(
		&f.Sort,
		"sort",
		"s",
		output.DomainSortColumn,
		output.RewriteListSortColumns().Usage(),
	)
}

// Validate refuses a sort column the list table does not have.
//
// Returns:
//   - error: an error wrapping [output.ErrUnknownSortColumn] for an unknown
//     column.
func (f *RewriteListFlags) Validate() error {
	err := output.RewriteListSortColumns().Check(f.Sort)
	if err != nil {
		return fmt.Errorf("check --sort: %w", err)
	}

	return nil
}

// Bind registers the file, sort, and instance-selection flags and binds their
// values to the receiver.
//
// Parameters:
//   - flags: flag set that receives the diff flags.
func (f *RewriteDiffFlags) Bind(flags *pflag.FlagSet) {
	flags.StringVarP(&f.File, "file", "f", "", "path to YAML/JSON rewrite rules file")
	f.InstanceSelection.Bind(flags)
	flags.StringVarP(
		&f.Sort,
		"sort",
		"s",
		output.DomainSortColumn,
		output.RewriteDiffSortColumns().Usage(),
	)
}

// Validate refuses a sort column the diff table does not have.
//
// Returns:
//   - error: an error wrapping [output.ErrUnknownSortColumn] for an unknown
//     column.
func (f *RewriteDiffFlags) Validate() error {
	err := output.RewriteDiffSortColumns().Check(f.Sort)
	if err != nil {
		return fmt.Errorf("check --sort: %w", err)
	}

	return nil
}
