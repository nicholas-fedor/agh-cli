// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"context"
	"errors"
	"fmt"
)

// MigrationRequest contains the inputs for one migration run.
type MigrationRequest struct {
	// DryRun previews the migration without writing to the credential store or
	// the configuration file.
	DryRun bool
}

// MigrationResult reports the outcome for one legacy plaintext instance.
type MigrationResult struct {
	// Instance is the instance name that was migrated or previewed.
	Instance string
	// Key is the keyring key that receives the password.
	Key string
	// DryRun reports that the instance was previewed rather than migrated.
	DryRun bool
	// Migrated reports that the password reached the credential store and the
	// configuration no longer writes it.
	Migrated bool
	// Err explains why the instance was not migrated. Its message never contains
	// a secret. It is nil for a successful migration.
	Err error
}

// MigrationReport contains the outcome of one migration run.
type MigrationReport struct {
	// Backend is the credential store backend name.
	Backend string
	// Service is the credential store namespace that receives the passwords.
	Service string
	// DryRun reports that nothing was written to the store or the file.
	DryRun bool
	// Results contains one entry per legacy plaintext instance in configuration
	// order.
	Results []MigrationResult
	// Saved reports whether the configuration file was rewritten.
	Saved bool
	// Err explains why the configuration was not rewritten. Its message never
	// contains a secret. A save failure leaves every plaintext password on disk,
	// so a repeated run stays safe.
	Err error
}

// migrationCandidate is one legacy plaintext instance selected for migration.
type migrationCandidate struct {
	// name is the instance name, which is also the default credential key.
	name string
	// key is the credential key that receives the password.
	key string
	// password is the legacy plaintext password. It is never formatted into a
	// result or an error.
	password string
}

// ErrPartialMigration reports that at least one legacy instance kept its plaintext
// password because the migration did not complete.
var ErrPartialMigration = errors.New("some credentials were not migrated")

// Migrate moves legacy plaintext passwords into the credential store.
//
// Migration is explicit, because a normal read must never migrate implicitly. An
// instance that already declares a credential source is skipped, so a configured
// source is never changed silently. For every candidate the password reaches the
// credential store first and the plaintext password is only dropped from the
// in-memory configuration afterwards, so a failed write leaves that instance
// exactly as it was. The configuration file is written once after every candidate
// is processed.
//
// A dry run performs no write, so it touches neither the credential store nor the
// configuration file.
//
// Parameters:
//   - ctx: context checked before the credential store calls.
//   - request: migration inputs, including the dry-run selection.
//
// Returns:
//   - MigrationReport: one outcome per legacy instance.
//   - error: a wrapped error when the store cannot be probed, at least one
//     instance failed, or the configuration could not be written.
func (a *Credentials) Migrate(
	ctx context.Context,
	request MigrationRequest,
) (MigrationReport, error) {
	service := a.service()
	report := MigrationReport{
		Backend: a.store.Backend(),
		Service: service,
		DryRun:  request.DryRun,
		Results: make([]MigrationResult, 0),
	}

	candidates := a.legacyPasswords()
	if len(candidates) == 0 {
		return report, nil
	}

	if request.DryRun {
		report.Results = previewMigrations(candidates)

		return report, nil
	}

	err := a.probe(ctx, service, candidates[0].key)
	if err != nil {
		return report, fmt.Errorf(
			"migrate %d credential(s) to service %q: %w",
			len(candidates),
			service,
			err,
		)
	}

	report.Results = a.migrateCandidates(ctx, service, candidates)

	report.Saved, report.Err = a.save()
	if report.Err != nil {
		report.Err = fmt.Errorf("migrate credentials: %w", report.Err)

		return report, report.Err
	}

	failed := failedMigrations(report.Results)
	if failed > 0 {
		return report, fmt.Errorf(
			"%w: %d of %d credentials",
			ErrPartialMigration,
			failed,
			len(candidates),
		)
	}

	return report, nil
}

// legacyPasswords returns the instances eligible for migration.
//
// An instance is eligible when it has no credential reference and a non-empty
// password. An instance that already declares a source, including an explicit
// plaintext source, is skipped so a configured source is never changed silently.
//
// Returns:
//   - []migrationCandidate: candidates in configuration order.
func (a *Credentials) legacyPasswords() []migrationCandidate {
	instances := a.local.Instances()
	names := a.local.OrderedNames()
	candidates := make([]migrationCandidate, 0, len(names))

	for _, name := range names {
		cfg := instances[name]
		if cfg.Credential != nil || cfg.Password == "" {
			continue
		}

		candidates = append(candidates, migrationCandidate{
			name:     name,
			key:      name,
			password: cfg.Password,
		})
	}

	return candidates
}

// migrateCandidates writes every candidate password to the credential store.
//
// A failing instance does not stop the remaining instances, because every outcome
// is reported and a partial migration must be visible.
//
// Parameters:
//   - ctx: context checked before the credential store calls.
//   - service: credential store namespace.
//   - candidates: legacy instances in configuration order.
//
// Returns:
//   - []MigrationResult: one outcome per candidate in the same order.
func (a *Credentials) migrateCandidates(
	ctx context.Context,
	service string,
	candidates []migrationCandidate,
) []MigrationResult {
	results := make([]MigrationResult, 0, len(candidates))

	for _, candidate := range candidates {
		results = append(results, a.migrateOne(ctx, service, candidate))
	}

	return results
}

// migrateOne writes one legacy password to the credential store and drops the
// plaintext password afterwards.
//
// The order is inherited from storeCredential, so a failed write leaves the
// candidate exactly as it was and its plaintext password keeps working.
//
// Parameters:
//   - ctx: context checked before the credential store call.
//   - service: credential store namespace.
//   - candidate: legacy instance to migrate.
//
// Returns:
//   - MigrationResult: the outcome for the candidate.
func (a *Credentials) migrateOne(
	ctx context.Context,
	service string,
	candidate migrationCandidate,
) MigrationResult {
	result := MigrationResult{Instance: candidate.name, Key: candidate.key}

	err := a.storeCredential(ctx, service, candidate.name, candidate.key, candidate.password)
	if err != nil {
		result.Err = err

		return result
	}

	result.Migrated = true

	return result
}

// probe reports whether the credential store answers a read.
//
// The store cannot enumerate its entries, so availability is decided by reading the
// first candidate key exactly once before any write. An absent credential proves
// the store is usable, because a store that cannot be read fails the probe instead
// of reporting an absent credential.
//
// Parameters:
//   - ctx: context checked before the credential store call.
//   - service: credential store namespace.
//   - key: credential key used for the probe.
//
// Returns:
//   - error: a wrapped sentinel error when the store cannot be read.
func (a *Credentials) probe(ctx context.Context, service, key string) error {
	_, err := a.stored(ctx, service, key)
	if err != nil {
		return fmt.Errorf("probe credential store service %q: %w", service, err)
	}

	return nil
}

// failedMigrations counts the candidate outcomes that did not complete.
//
// Parameters:
//   - results: migration outcomes in configuration order.
//
// Returns:
//   - int: the number of outcomes carrying an error.
func failedMigrations(results []MigrationResult) int {
	failed := 0

	for _, result := range results {
		if result.Err != nil {
			failed++
		}
	}

	return failed
}

// previewMigrations describes a migration without writing anything.
//
// Parameters:
//   - candidates: legacy instances in configuration order.
//
// Returns:
//   - []MigrationResult: one preview per candidate in the same order.
func previewMigrations(candidates []migrationCandidate) []MigrationResult {
	results := make([]MigrationResult, 0, len(candidates))

	for _, candidate := range candidates {
		results = append(results, MigrationResult{
			Instance: candidate.name,
			Key:      candidate.key,
			DryRun:   true,
		})
	}

	return results
}
