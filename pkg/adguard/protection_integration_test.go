// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// TestClientProtectionOperationsEndToEnd verifies authenticated protection workflows.
func TestClientProtectionOperationsEndToEnd(t *testing.T) {
	t.Parallel()

	tests := protectionIntegrationSuccessCases()

	server, requests := newDNSIntegrationSuccessServer(t, tests)
	client := newDNSIntegrationClient(t, server)

	for index := range tests {
		test := &tests[index]
		result, err := test.invoke(t.Context(), client)
		request := <-requests

		assertDNSIntegrationRequest(t, request, test)
		require.NoError(t, err, test.name)

		if test.verify != nil {
			test.verify(t, result)
		}
	}
}

// TestClientProtectionStructuredErrors verifies protection failures retain HTTP metadata.
func TestClientProtectionStructuredErrors(t *testing.T) {
	t.Parallel()

	tests := protectionIntegrationErrorCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testDNSIntegrationError(t, &test)
		})
	}
}

// protectionIntegrationSuccessCases returns protection and cache-clear exchanges.
func protectionIntegrationSuccessCases() []dnsIntegrationSuccessCase {
	return []dnsIntegrationSuccessCase{
		{
			name:        "protection",
			method:      http.MethodPost,
			path:        "/api/control/protection",
			requestBody: `{"enabled":true,"duration":900}`,
			invoke: func(ctx context.Context, client *adguard.Client) (any, error) {
				return nil, client.SetProtection(ctx, adguard.ProtectionConfig{
					Enabled:  true,
					Duration: new(uint64(900)),
				})
			},
		},
		{
			name:   "clear cache",
			method: http.MethodPost,
			path:   "/api/control/cache_clear",
			invoke: func(ctx context.Context, client *adguard.Client) (any, error) {
				return nil, client.ClearCache(ctx)
			},
		},
	}
}

// protectionIntegrationErrorCases returns structured protection failures.
func protectionIntegrationErrorCases() []dnsIntegrationErrorCase {
	return []dnsIntegrationErrorCase{
		{
			name:      "protection",
			operation: "set_protection",
			method:    http.MethodPost,
			path:      "/api/control/protection",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				return client.SetProtection(ctx, adguard.ProtectionConfig{Enabled: true})
			},
		},
		{
			name:      "clear cache",
			operation: "clear_cache",
			method:    http.MethodPost,
			path:      "/api/control/cache_clear",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				return client.ClearCache(ctx)
			},
		},
	}
}
