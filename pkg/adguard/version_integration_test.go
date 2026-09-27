// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// TestClientVersionOperationsEndToEnd verifies authenticated version lookups.
func TestClientVersionOperationsEndToEnd(t *testing.T) {
	t.Parallel()

	tests := versionIntegrationSuccessCases()

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

// TestClientVersionStructuredErrors verifies version failures retain HTTP metadata.
func TestClientVersionStructuredErrors(t *testing.T) {
	t.Parallel()

	tests := versionIntegrationErrorCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testDNSIntegrationError(t, &test)
		})
	}
}

// versionIntegrationSuccessCases returns the version information exchange.
func versionIntegrationSuccessCases() []dnsIntegrationSuccessCase {
	return []dnsIntegrationSuccessCase{
		{
			name:        "version info",
			method:      http.MethodPost,
			path:        "/api/control/version.json",
			requestBody: `{"recheck_now":true}`,
			responseBody: `{
				"disabled":false,
				"new_version":"v0.108.0",
				"announcement":"AdGuard Home v0.108.0 is available",
				"announcement_url":"https://example.test/releases/v0.108.0",
				"can_autoupdate":false
			}`,
			responseContentType: blockedServicesIntegrationJSONContentType,
			invoke: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.GetVersionInfo(ctx, new(true))
			},
			verify: func(t *testing.T, result any) {
				t.Helper()

				versionInfo, ok := result.(*adguard.VersionInfo)
				require.True(t, ok)
				assert.Equal(t, &adguard.VersionInfo{
					Disabled:        false,
					NewVersion:      new("v0.108.0"),
					Announcement:    new("AdGuard Home v0.108.0 is available"),
					AnnouncementURL: new("https://example.test/releases/v0.108.0"),
					CanAutoupdate:   new(false),
				}, versionInfo)
			},
		},
	}
}

// versionIntegrationErrorCases returns the structured version failure.
func versionIntegrationErrorCases() []dnsIntegrationErrorCase {
	return []dnsIntegrationErrorCase{
		{
			name:      "version info",
			operation: "get_version_info",
			method:    http.MethodPost,
			path:      "/api/control/version.json",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.GetVersionInfo(ctx, nil)

				return err
			},
		},
	}
}
