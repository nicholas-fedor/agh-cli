// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"fmt"
)

// UsernameResult reports the outcome of changing one instance username.
//
// The result describes configuration state only. A username is not a secret, so
// it is reported directly, and no value derived from a password ever appears
// here.
type UsernameResult struct {
	// Instance is the instance whose username changed.
	Instance string
	// Username is the recorded administrator username. It is empty after a clear.
	Username string
	// Saved reports whether the configuration file was rewritten. A false value
	// means the in-memory change did not reach disk and the write is retryable.
	Saved bool
}

// UsernameStatus reports the configured username of one named instance.
type UsernameStatus struct {
	// Instance is the instance name whose username was inspected.
	Instance string
	// Username is the configured AdGuard Home administrator username. It is empty
	// when no username is configured, which means the instance authenticates with
	// no username at all.
	Username string
}

// UsernameReport reports the configured username of the named instances.
//
// A username is configuration rather than a secret, so this report is free of any
// credential store detail. The store is not consulted to answer it.
type UsernameReport struct {
	// Instances contains one entry per named instance in configuration order.
	Instances []UsernameStatus
}

// SetUsername records the AdGuard Home administrator username of one configured
// instance and writes the configuration file.
//
// The username and the stored password are independent. A username is
// configuration rather than a secret, so it lives in the configuration file and
// this use case never reads or writes the credential store. Changing a username
// therefore leaves a working password in place, and setting a password never
// disturbs the username.
//
// The method takes no context because it never reaches the credential store.
// A context on this type guards a blocking platform call, and a configuration
// file write is neither blocking nor cancellable.
//
// Parameters:
//   - name: configured instance name.
//   - username: AdGuard Home administrator username.
//
// Returns:
//   - UsernameResult: the instance, the recorded username, and whether the
//     configuration was rewritten.
//   - error: a wrapped error when the instance is unknown or the configuration
//     cannot be written.
func (a *Credentials) SetUsername(name, username string) (UsernameResult, error) {
	err := a.local.SetUsername(name, username)
	if err != nil {
		return UsernameResult{}, fmt.Errorf("set username for instance %q: %w", name, err)
	}

	saved, err := a.save()
	if err != nil {
		return UsernameResult{Instance: name, Username: username}, fmt.Errorf(
			"set username for instance %q: %w",
			name,
			err,
		)
	}

	return UsernameResult{Instance: name, Username: username, Saved: saved}, nil
}

// ClearUsername removes the AdGuard Home administrator username of one configured
// instance and writes the configuration file.
//
// Only the username is removed. A stored credential reference and a plaintext
// password both survive, so clearing a username never detaches an instance from
// its credential source and a working password keeps working.
//
// Clearing an instance that has no username is not an error, so repeating the
// call is safe.
//
// Parameters:
//   - name: configured instance name.
//
// Returns:
//   - UsernameResult: the instance, the empty username, and whether the
//     configuration was rewritten.
//   - error: a wrapped error when the instance is unknown or the configuration
//     cannot be written.
func (a *Credentials) ClearUsername(name string) (UsernameResult, error) {
	err := a.local.ClearUsername(name)
	if err != nil {
		return UsernameResult{}, fmt.Errorf("clear username for instance %q: %w", name, err)
	}

	saved, err := a.save()
	if err != nil {
		return UsernameResult{Instance: name}, fmt.Errorf(
			"clear username for instance %q: %w",
			name,
			err,
		)
	}

	return UsernameResult{Instance: name, Saved: saved}, nil
}

// StatusUsername reports the configured username of the named instances.
//
// The report never consults the credential store, because a username is
// configuration and a presence question about a password is answered by
// [Credentials.StatusPassword].
//
// Parameters:
//   - names: instance names to inspect, or an empty slice to inspect every
//     configured instance in configuration order.
//
// Returns:
//   - UsernameReport: one entry per inspected instance.
//   - error: a wrapped error when a requested name is unknown.
func (a *Credentials) StatusUsername(names []string) (UsernameReport, error) {
	selected, err := a.statusConfigs(names)
	if err != nil {
		return UsernameReport{}, fmt.Errorf("select instances for username status: %w", err)
	}

	report := UsernameReport{
		Instances: make([]UsernameStatus, 0, len(selected)),
	}

	for _, cfg := range selected {
		report.Instances = append(report.Instances, UsernameStatus{
			Instance: cfg.Name,
			Username: cfg.Username,
		})
	}

	return report, nil
}
