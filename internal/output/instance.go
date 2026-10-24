// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package output

import (
	"fmt"
	"io"

	"github.com/nicholas-fedor/agh-cli/internal/app"
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

// WriteInstanceNames writes one configured instance name per line.
//
// Parameters:
//   - writer: destination for the names.
//   - configs: configured instances in selection order.
//
// Returns:
//   - error: a wrapped error when a name cannot be written.
func WriteInstanceNames(writer io.Writer, configs []instance.Config) error {
	for _, cfg := range configs {
		_, err := fmt.Fprintln(writer, cfg.Name)
		if err != nil {
			return fmt.Errorf("write instance %q: %w", cfg.Name, err)
		}
	}

	return nil
}

// WriteInstanceAdded writes the outcome of an added instance.
//
// Parameters:
//   - writer: destination for the outcome.
//   - name: added instance name.
//
// Returns:
//   - error: a wrapped error when the outcome cannot be written.
func WriteInstanceAdded(writer io.Writer, name string) error {
	_, err := fmt.Fprintf(writer, "Instance %q added\n", name)
	if err != nil {
		return fmt.Errorf("write instance outcome: %w", err)
	}

	return nil
}

// WriteInstanceRemoval writes the outcome of one removed instance and of the
// password it kept in the credential store.
//
// Parameters:
//   - writer: destination for the outcome.
//   - result: outcome of the removal.
//
// Returns:
//   - error: a wrapped error when the outcome cannot be written.
func WriteInstanceRemoval(writer io.Writer, result app.InstanceRemoveResult) error {
	_, err := fmt.Fprintf(writer, "Instance %q removed\n", result.Instance)
	if err == nil {
		err = writeRemovedCredential(writer, result)
	}

	if err != nil {
		return fmt.Errorf("write instance outcome: %w", err)
	}

	return nil
}

// WriteFailedInstanceRemoval writes the credential outcome of a removal that
// did not finish.
//
// The credential store entry is deleted before the configuration is written, so
// a write failure leaves the instance configured with its password already gone.
// That state is reported rather than left to be inferred from the error, because
// the operator otherwise cannot tell whether the secret is still stored. A
// removal that deleted nothing reports nothing: the failure says it all, and the
// instance is untouched.
//
// Parameters:
//   - writer: destination for the outcome.
//   - result: partial outcome of the failed removal.
//
// Returns:
//   - error: a wrapped error when the outcome cannot be written.
func WriteFailedInstanceRemoval(writer io.Writer, result app.InstanceRemoveResult) error {
	if !result.Removed {
		return nil
	}

	_, err := fmt.Fprintf(
		writer,
		"Removed credential for instance %q with key %q from service %q. "+
			"Instance %q remains configured; run the command again to remove it.\n",
		result.Instance,
		result.Key,
		result.Service,
		result.Instance,
	)
	if err != nil {
		return fmt.Errorf("write instance outcome: %w", err)
	}

	return nil
}

// writeRemovedCredential writes what happened to the stored password of a
// removed instance.
//
// Parameters:
//   - writer: destination for the outcome.
//   - result: outcome of the removal.
//
// Returns:
//   - error: the write error, or nil when the instance kept no stored password.
func writeRemovedCredential(writer io.Writer, result app.InstanceRemoveResult) error {
	var err error

	switch {
	case result.Key == "":
		return nil
	case result.Shared:
		_, err = fmt.Fprintf(
			writer,
			"Kept credential with key %q in service %q: another configured "+
				"instance still reads its password through it.\n",
			result.Key,
			result.Service,
		)
	case !result.Removed:
		_, err = fmt.Fprintf(
			writer,
			"No stored credential for instance %q with key %q in service %q.\n",
			result.Instance,
			result.Key,
			result.Service,
		)
	default:
		_, err = fmt.Fprintf(
			writer,
			"Removed credential for instance %q with key %q from service %q.\n",
			result.Instance,
			result.Key,
			result.Service,
		)
	}

	if err != nil {
		return fmt.Errorf("write removed credential: %w", err)
	}

	return nil
}
