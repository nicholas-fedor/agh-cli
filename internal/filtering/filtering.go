// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package filtering

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// ConfigRequest contains the filtering settings to apply.
type ConfigRequest struct {
	// Enabled controls whether filtering is enabled.
	Enabled bool
	// Interval is the automatic filter refresh interval in hours.
	Interval int64
}

// URLRequest identifies a filtering subscription mutation.
type URLRequest struct {
	// Name is the subscription display name used when adding a subscription.
	Name string
	// URL is the subscription location.
	URL string
	// Whitelist selects or identifies allowlist mode.
	Whitelist bool
}

// Subscription describes one filtering subscription in a status result.
type Subscription struct {
	// Enabled reports whether the subscription is enabled.
	Enabled bool
	// ID is the subscription identifier.
	ID int64
	// LastUpdated is the most recent subscription update time.
	LastUpdated *time.Time
	// Name is the subscription display name.
	Name string
	// RulesCount is the number of rules in the subscription.
	RulesCount uint32
	// URL is the subscription location.
	URL string
}

// Status contains the presence-aware filtering configuration snapshot.
type Status struct {
	// Enabled is the optional filtering service state.
	Enabled *bool
	// Interval is the optional automatic filter refresh interval.
	Interval *int64
	// Filters is the optional filtering subscription list.
	Filters *[]Subscription
	// WhitelistFilters is the optional allowlist subscription list.
	WhitelistFilters *[]Subscription
	// UserRules is the optional custom filtering rule list.
	UserRules *[]string
}

// Service executes filtering-management use cases through the public AdGuard service.
type Service struct {
	filtering adguard.FilteringService
}

// errNilStatus reports an invalid successful response without status data.
var errNilStatus = errors.New("filtering service returned nil status")

// NewService creates a filtering-management use-case service.
//
// Parameters:
//   - filtering: public AdGuard filtering service backing the use cases.
//
// Returns:
//   - *Service: use-case service wrapping the public service.
func NewService(filtering adguard.FilteringService) *Service {
	return &Service{filtering: filtering}
}

// AddURL adds a filtering subscription.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: subscription values sent to AdGuard Home.
//
// Returns:
//   - error: a wrapped subscription-creation error.
func (s *Service) AddURL(ctx context.Context, request URLRequest) error {
	wireRequest := adguard.AddFilteringURLRequest{
		Name:      new(request.Name),
		URL:       new(request.URL),
		Whitelist: new(request.Whitelist),
	}

	err := s.filtering.AddFilteringURL(ctx, wireRequest)
	if err != nil {
		return fmt.Errorf("add filtering URL: %w", err)
	}

	return nil
}

// RemoveURL removes a filtering subscription.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: subscription location and allowlist mode.
//
// Returns:
//   - error: a wrapped subscription-deletion error.
func (s *Service) RemoveURL(ctx context.Context, request URLRequest) error {
	wireRequest := adguard.RemoveFilteringURLRequest{
		URL:       new(request.URL),
		Whitelist: new(request.Whitelist),
	}

	err := s.filtering.RemoveFilteringURL(ctx, wireRequest)
	if err != nil {
		return fmt.Errorf("remove filtering URL: %w", err)
	}

	return nil
}

// Status retrieves and shapes the current filtering configuration.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//
// Returns:
//   - Status: presence-aware snapshot of the filtering configuration.
//   - error: a wrapped status error, or errNilStatus for a successful response
//     without status data.
func (s *Service) Status(ctx context.Context) (Status, error) {
	status, err := s.filtering.FilteringStatus(ctx)
	if err != nil {
		return Status{}, fmt.Errorf("get filtering status: %w", err)
	}
	if status == nil {
		return Status{}, errNilStatus
	}

	return Status{
		Enabled:          clonePointer(status.Enabled),
		Interval:         clonePointer(status.Interval),
		Filters:          shapeSubscriptions(status.Filters),
		WhitelistFilters: shapeSubscriptions(status.WhitelistFilters),
		UserRules:        cloneSlice(status.UserRules),
	}, nil
}

// UpdateConfig applies the requested filtering configuration.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: filtering settings sent to AdGuard Home.
//
// Returns:
//   - error: a wrapped configuration-update error.
func (s *Service) UpdateConfig(ctx context.Context, request ConfigRequest) error {
	config := adguard.FilteringConfig{
		Enabled:  new(request.Enabled),
		Interval: new(request.Interval),
	}

	err := s.filtering.UpdateFilteringConfig(ctx, config)
	if err != nil {
		return fmt.Errorf("update filtering config: %w", err)
	}

	return nil
}

// clonePointer copies one optional value.
//
// Parameters:
//   - value: optional value to copy.
//
// Returns:
//   - *T: an independent copy, or nil for absent input.
func clonePointer[T any](value *T) *T {
	if value == nil {
		return nil
	}

	return new(*value)
}

// cloneSlice copies one optional slice while preserving its presence.
//
// Parameters:
//   - values: optional slice to copy.
//
// Returns:
//   - *[]T: an independent copy, or nil for absent input.
func cloneSlice[T any](values *[]T) *[]T {
	if values == nil {
		return nil
	}

	cloned := slices.Clone(*values)

	return &cloned
}

// shapeSubscriptions converts wire subscriptions into domain results.
//
// Parameters:
//   - values: optional wire subscriptions; nil stays nil.
//
// Returns:
//   - *[]Subscription: domain subscriptions, or nil for absent input.
func shapeSubscriptions(values *[]adguard.FilterSubscription) *[]Subscription {
	if values == nil {
		return nil
	}

	shaped := make([]Subscription, 0, len(*values))
	for _, value := range *values {
		shaped = append(shaped, Subscription{
			Enabled:     value.Enabled,
			ID:          value.ID,
			LastUpdated: clonePointer(value.LastUpdated),
			Name:        value.Name,
			RulesCount:  value.RulesCount,
			URL:         value.URL,
		})
	}

	return &shaped
}
