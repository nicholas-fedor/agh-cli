// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package instance

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"
)

// SelectionMode identifies how [Catalog.Select] chooses instance targets.
//
// Use ExplicitOrDefaultSelection to honor explicit names and implicit fallback,
// or AllSelection to select every catalog entry in order.
type SelectionMode uint8

// Source is the configured instance mapping keyed by instance name.
//
// Each value is the raw settings mapping read from the configuration, so every
// catalog entry is validated from the same shape. The zero value is an empty
// source.
type Source map[string]map[string]any

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
	// ErrDuplicateInstance indicates that a catalog contains a duplicate identity.
	ErrDuplicateInstance = errors.New("duplicate instance")
	// ErrEmptyCatalog indicates that no instances are configured.
	ErrEmptyCatalog = errors.New("no instances configured")
	// ErrInvalidSelection indicates an unsupported target-selection mode.
	ErrInvalidSelection = errors.New("invalid instance selection mode")
	// ErrNoConfigInstances indicates that the raw configuration has no instance map.
	ErrNoConfigInstances = errors.New("no instances configured in config file")
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
//   - error: a wrapped validation error for an invalid configuration, or
//     ErrDuplicateInstance when two configurations have the same identity.
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

		entries = append(entries, validated)
		byID[id] = validated
	}

	return Catalog{entries: entries, byID: byID}, nil
}

// SourceFromValue converts a configuration-loader value into a Source.
//
// The conversion is checked instead of assumed, because a mistyped instance
// stanza must never be skipped silently and fall back to another instance. A nil
// value is an absent mapping and converts to an empty source, so a missing
// configuration is reported by catalog selection instead of conversion.
//
// Parameters:
//   - value: raw configuration value read by the configuration loader.
//
// Returns:
//   - Source: the converted instance mappings, or an empty source for a nil
//     value.
//   - error: ErrNoConfigInstances when the value is not a mapping, or a wrapped
//     ErrInvalidConfig when an instance entry is not a mapping.
func SourceFromValue(value any) (Source, error) {
	if value == nil {
		return Source{}, nil
	}

	rawInstances, ok := value.(map[string]any)
	if !ok {
		return nil, ErrNoConfigInstances
	}

	source := make(Source, len(rawInstances))
	for name, settings := range rawInstances {
		raw, isMapping := settings.(map[string]any)
		if !isMapping {
			return nil, fmt.Errorf("%w: %s", ErrInvalidConfig, name)
		}

		source[name] = raw
	}

	return source, nil
}

// CatalogFromSource converts a configured instance source into a validated
// catalog.
//
// Instance names are sorted before validation so AllSelection retains the
// deterministic order used by the CLI. The complete catalog is validated before
// any selection can occur. Configured credentials are validated but left
// unresolved; use [CatalogFromSourceResolved] to resolve them.
//
// Parameters:
//   - source: configured instance mappings.
//
// Returns:
//   - Catalog: an ordered catalog containing every validated configuration.
//   - error: a wrapped configuration validation error or a wrapped catalog
//     validation error.
func CatalogFromSource(source Source) (Catalog, error) {
	names := slices.Sorted(maps.Keys(source))
	configs := make([]Config, 0, len(source))

	for _, name := range names {
		cfg, err := ConfigFromMap(name, source[name])
		if err != nil {
			return Catalog{}, fmt.Errorf("parse instance %q: %w", name, err)
		}

		configs = append(configs, cfg)
	}

	catalog, err := NewCatalog(configs)
	if err != nil {
		return Catalog{}, fmt.Errorf("create catalog: %w", err)
	}

	return catalog, nil
}

// CatalogFromSourceResolved converts a configured instance source into a
// validated catalog whose credentials have been resolved.
//
// The complete catalog is validated before any credential is looked up, so an
// invalid configuration never reaches a credential source. Every resolver sees
// a validated configuration in catalog order, and the resolved configurations
// are validated again before the catalog is returned. A nil resolver leaves
// credentials unresolved, which matches [CatalogFromSource].
//
// Parameters:
//   - ctx: context governing credential resolution.
//   - source: configured instance mappings.
//   - resolve: resolver applied to every catalog entry, or nil to leave
//     credentials unresolved.
//
// Returns:
//   - Catalog: an ordered catalog containing every resolved configuration.
//   - error: a wrapped configuration validation error, a wrapped credential
//     resolution error, or a wrapped catalog validation error.
func CatalogFromSourceResolved(
	ctx context.Context,
	source Source,
	resolve CredentialResolver,
) (Catalog, error) {
	catalog, err := CatalogFromSource(source)
	if err != nil {
		return Catalog{}, fmt.Errorf("create catalog: %w", err)
	}

	resolved, err := resolveCatalog(ctx, catalog, resolve)
	if err != nil {
		return Catalog{}, fmt.Errorf("create resolved catalog: %w", err)
	}

	return resolved, nil
}

// resolveCatalog resolves the credentials of every catalog entry.
//
// Parameters:
//   - ctx: context governing credential resolution.
//   - catalog: validated catalog whose entries are resolved.
//   - resolve: resolver applied to every entry, or nil to leave credentials
//     unresolved.
//
// Returns:
//   - Catalog: catalog holding the resolved configurations, or catalog when no
//     resolver is supplied.
//   - error: a wrapped resolution error naming the failing instance, or a
//     wrapped validation error for a resolved configuration.
func resolveCatalog(
	ctx context.Context,
	catalog Catalog,
	resolve CredentialResolver,
) (Catalog, error) {
	if resolve == nil {
		return catalog, nil
	}

	configs := catalog.All()
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

// All returns a defensive snapshot of all configurations in catalog order.
//
// Returns:
//   - []Config: an independent slice containing the catalog configurations.
func (c Catalog) All() []Config {
	return append([]Config(nil), c.entries...)
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
