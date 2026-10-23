// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"context"
	"errors"
	"fmt"
)

// SelectionMode identifies how [Catalog.Select] chooses instance targets.
//
// Use ExplicitOrDefaultSelection to honor explicit names and implicit fallback,
// or AllSelection to select every catalog entry in order.
type SelectionMode uint8

// Catalog is an immutable, ordered collection of validated instance
// configurations. Its zero value is an empty catalog.
type Catalog struct {
	// entries contains validated configurations in their supplied order.
	entries []Config
	// byID indexes the same configurations by their mapping-derived identity.
	byID map[ID]Config
}

const (
	// ExplicitOrDefaultSelection uses explicit names, then default, then singleton fallback.
	ExplicitOrDefaultSelection SelectionMode = iota
	// AllSelection selects every catalog entry in catalog order.
	AllSelection
)

// defaultInstanceName is the implicit target name.
const defaultInstanceName = "default"

var (
	// ErrConflictingInstance indicates that two catalog identities differ only by
	// letter case.
	ErrConflictingInstance = errors.New("instance names differ only by letter case")
	// ErrDuplicateInstance indicates that a catalog contains a duplicate identity.
	ErrDuplicateInstance = errors.New("duplicate instance")
	// ErrEmptyCatalog indicates that no instances are configured.
	ErrEmptyCatalog = errors.New("no instances configured")
	// ErrInvalidSelection indicates an unsupported target-selection mode.
	ErrInvalidSelection = errors.New("invalid instance selection mode")
	// ErrTargetSelection indicates that target selection is ambiguous.
	ErrTargetSelection = errors.New(
		"specify --instance <name> or --all, or configure a 'default' instance",
	)
	// ErrUnknownInstance indicates that an instance identity is not in the catalog.
	ErrUnknownInstance = errors.New("unknown instance")
)

// NewCatalog validates configurations and preserves their supplied order.
//
// Parameters:
//   - configs: instance configurations to validate and index.
//
// Returns:
//   - Catalog: an ordered catalog containing each validated configuration.
//   - error: a wrapped validation error for an invalid configuration,
//     ErrDuplicateInstance when two configurations have the same identity, or
//     ErrConflictingInstance when two identities differ only by letter case.
func NewCatalog(configs []Config) (Catalog, error) {
	entries := make([]Config, 0, len(configs))
	byID := make(map[ID]Config, len(configs))

	for _, cfg := range configs {
		validated, err := cfg.Validate()
		if err != nil {
			return Catalog{}, fmt.Errorf("validate instance %q: %w", cfg.Name, err)
		}

		id := validated.Identity()
		if _, exists := byID[id]; exists {
			return Catalog{}, fmt.Errorf("%w: %q", ErrDuplicateInstance, id)
		}

		if conflict, found := conflictingIdentity(entries, id); found {
			return Catalog{}, fmt.Errorf("%w: %q and %q", ErrConflictingInstance, conflict, id)
		}

		entries = append(entries, validated)
		byID[id] = validated
	}

	return Catalog{entries: entries, byID: byID}, nil
}

// conflictingIdentity returns the entry identity that differs from id only by
// letter case.
//
// Parameters:
//   - entries: configurations already accepted into the catalog.
//   - id: identity of the configuration being added.
//
// Returns:
//   - ID: the conflicting identity, or an empty identity when none conflicts.
//   - bool: true when an entry conflicts with id.
func conflictingIdentity(entries []Config, id ID) (ID, bool) {
	for _, entry := range entries {
		if entry.Identity().ConflictsWith(id) {
			return entry.Identity(), true
		}
	}

	return "", false
}

// All returns a defensive snapshot of all configurations in catalog order.
//
// Returns:
//   - []Config: an independent slice containing the catalog configurations.
func (c Catalog) All() []Config {
	return append([]Config(nil), c.entries...)
}

// Resolve returns a catalog whose credentials have been resolved.
//
// The catalog is already validated, so an invalid configuration never reaches a
// credential source. Every resolver call sees a validated configuration in
// catalog order, and the resolved configurations are validated again before the
// catalog is returned, so a resolver cannot add an invalid configuration.
//
// Parameters:
//   - ctx: context governing credential resolution.
//   - resolve: resolver applied to every entry, or nil to leave credentials
//     unresolved.
//
// Returns:
//   - Catalog: catalog holding the resolved configurations, or c when no
//     resolver is supplied.
//   - error: a wrapped resolution error naming the failing instance, or a
//     wrapped validation error for a resolved configuration.
func (c Catalog) Resolve(ctx context.Context, resolve CredentialResolver) (Catalog, error) {
	if resolve == nil {
		return c, nil
	}

	configs := c.All()
	for index, cfg := range configs {
		resolved, err := resolve.Resolve(ctx, cfg)
		if err != nil {
			return Catalog{}, fmt.Errorf(
				"resolve credentials for instance %q: %w",
				cfg.Name,
				err,
			)
		}

		configs[index] = resolved
	}

	resolvedCatalog, err := NewCatalog(configs)
	if err != nil {
		return Catalog{}, fmt.Errorf("validate resolved instance: %w", err)
	}

	return resolvedCatalog, nil
}

// Select resolves targets according to mode and returns them in execution
// order.
//
// AllSelection uses catalog order. ExplicitOrDefaultSelection uses the first
// occurrence of each explicit name, then falls back to the default instance or
// a sole catalog entry when no names are supplied.
//
// Parameters:
//   - names: explicit instance names to select.
//   - mode: target-selection policy.
//
// Returns:
//   - []Config: selected configurations in execution order.
//   - error: ErrEmptyCatalog, ErrInvalidSelection, ErrUnknownInstance, or
//     ErrTargetSelection, including contextual wrapping where applicable.
func (c Catalog) Select(
	names []string,
	mode SelectionMode,
) ([]Config, error) {
	if len(c.entries) == 0 {
		return nil, ErrEmptyCatalog
	}

	switch mode {
	case AllSelection:
		return c.All(), nil
	case ExplicitOrDefaultSelection:
		selected, err := c.selectExplicitOrDefault(names)
		if err != nil {
			return nil, fmt.Errorf("select explicit or default: %w", err)
		}

		return selected, nil
	default:
		return nil, ErrInvalidSelection
	}
}

// selectExplicit resolves known names by first occurrence without duplicates.
//
// Parameters:
//   - names: explicit instance names to resolve.
//
// Returns:
//   - []Config: selected configurations in first-occurrence order.
//   - error: ErrUnknownInstance when a name is absent from the catalog.
func (c Catalog) selectExplicit(names []string) ([]Config, error) {
	selected := make([]Config, 0, len(names))
	seen := make(map[ID]struct{}, len(names))

	for _, name := range names {
		cfg, ok := c.byID[ID(name)]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrUnknownInstance, name)
		}

		if _, exists := seen[cfg.Identity()]; exists {
			continue
		}

		seen[cfg.Identity()] = struct{}{}
		selected = append(selected, cfg)
	}

	return selected, nil
}

// selectExplicitOrDefault resolves explicit names or applies implicit fallback.
//
// Parameters:
//   - names: explicit instance names to resolve.
//
// Returns:
//   - []Config: explicit selections, the default instance, or the sole catalog
//     entry when applicable.
//   - error: a wrapped ErrUnknownInstance for invalid explicit names, or
//     ErrTargetSelection when implicit selection is ambiguous.
func (c Catalog) selectExplicitOrDefault(names []string) ([]Config, error) {
	if len(names) > 0 {
		selected, err := c.selectExplicit(names)
		if err != nil {
			return nil, fmt.Errorf("select explicit: %w", err)
		}

		return selected, nil
	}

	if cfg, ok := c.byID[defaultInstanceName]; ok {
		return []Config{cfg}, nil
	}

	if len(c.entries) == 1 {
		return []Config{c.entries[0]}, nil
	}

	return nil, ErrTargetSelection
}
