// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package client

import (
	"context"
	"fmt"
	"slices"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// Service executes client-management use cases through the public AdGuard service.
type Service struct {
	clients adguard.ClientsService
}

// NewService creates a client-management use-case service.
//
// Parameters:
//   - clients: public AdGuard client service backing the use cases.
//
// Returns:
//   - *Service: use-case service wrapping the public service.
func NewService(clients adguard.ClientsService) *Service {
	return &Service{clients: clients}
}

// Add creates a configured client.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: client values sent to AdGuard Home.
//
// Returns:
//   - error: a wrapped client-creation error.
func (s *Service) Add(ctx context.Context, request AddRequest) error {
	config := adguard.ClientConfig{
		Name:                     request.Name,
		IDs:                      request.IDs,
		UseGlobalSettings:        request.UseGlobalSettings,
		FilteringEnabled:         request.FilteringEnabled,
		ParentalEnabled:          request.ParentalEnabled,
		SafebrowsingEnabled:      request.SafebrowsingEnabled,
		SafesearchEnabled:        false,
		SafeSearch:               nil,
		UseGlobalBlockedServices: false,
		BlockedServicesSchedule:  nil,
		BlockedServices:          nil,
		Upstreams:                nil,
		Tags:                     nil,
		IgnoreQuerylog:           false,
		IgnoreStatistics:         false,
		UpstreamsCacheEnabled:    false,
		UpstreamsCacheSize:       0,
	}

	err := s.clients.ClientsAdd(ctx, config)
	if err != nil {
		return fmt.Errorf("add client: %w", err)
	}

	return nil
}

// Delete removes a configured client by name.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: name of the client to remove.
//
// Returns:
//   - error: a wrapped client-deletion error.
func (s *Service) Delete(ctx context.Context, request DeleteRequest) error {
	err := s.clients.ClientsDelete(ctx, adguard.ClientDelete{Name: request.Name})
	if err != nil {
		return fmt.Errorf("delete client: %w", err)
	}

	return nil
}

// List retrieves configured and automatically discovered clients.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//
// Returns:
//   - Result: rows for configured clients followed by discovered clients.
//   - error: a wrapped client-status error.
func (s *Service) List(ctx context.Context) (Result, error) {
	status, err := s.clients.ClientsStatus(ctx)
	if err != nil {
		return Result{}, fmt.Errorf("get clients: %w", err)
	}

	var rows []Row

	if count := len(status.Clients) + len(status.AutoClients); count > 0 {
		rows = make([]Row, 0, count)
	}

	for index := range status.Clients {
		rows = append(rows, Row{Name: status.Clients[index].Name, Automatic: false})
	}

	for index := range status.AutoClients {
		rows = append(rows, Row{Name: status.AutoClients[index].Name, Automatic: true})
	}

	return Result{Rows: rows}, nil
}

// Update applies a presence-sensitive patch to a configured client.
//
// Parameters:
//   - ctx: request-scoped cancellation signal.
//   - request: client values patched into the configuration.
//
// Returns:
//   - error: a wrapped client-update error.
func (s *Service) Update(ctx context.Context, request UpdateRequest) error {
	data := adguard.ClientUpdateData{
		Name:                new(request.Name),
		UseGlobalSettings:   new(request.UseGlobalSettings),
		FilteringEnabled:    new(request.FilteringEnabled),
		ParentalEnabled:     new(request.ParentalEnabled),
		SafebrowsingEnabled: new(request.SafebrowsingEnabled),
	}
	if len(request.IDs) > 0 {
		data.IDs = new(slices.Clone(request.IDs))
	}

	err := s.clients.ClientsUpdate(ctx, adguard.ClientUpdate{Name: request.Name, Data: &data})
	if err != nil {
		return fmt.Errorf("update client: %w", err)
	}

	return nil
}
