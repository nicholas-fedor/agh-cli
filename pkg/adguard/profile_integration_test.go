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

const (
	// The web-interface profile name used in realistic profile requests.
	profileIntegrationName = "operator"
	// The web-interface language used in realistic profile requests.
	profileIntegrationLanguage = "de"
	// The automatic web-interface theme used in realistic profile requests.
	profileIntegrationAutoTheme = "auto"
	// The dark web-interface theme used in realistic profile requests.
	profileIntegrationDarkTheme = "dark"
)

// TestClientProfileOperationsEndToEnd verifies authenticated profile workflows.
func TestClientProfileOperationsEndToEnd(t *testing.T) {
	t.Parallel()

	tests := profileIntegrationSuccessCases()

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

// TestClientProfileStructuredErrors verifies profile failures retain HTTP metadata.
func TestClientProfileStructuredErrors(t *testing.T) {
	t.Parallel()

	tests := profileIntegrationErrorCases()

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			testDNSIntegrationError(t, &test)
		})
	}
}

// profileIntegrationSuccessCases returns profile retrieval and update exchanges.
func profileIntegrationSuccessCases() []dnsIntegrationSuccessCase {
	return []dnsIntegrationSuccessCase{
		{
			name:   "get profile",
			method: http.MethodGet,
			path:   "/api/control/profile",
			responseBody: `{
				"name":"` + profileIntegrationName + `",
				"language":"` + profileIntegrationLanguage + `",
				"theme":"` + profileIntegrationAutoTheme + `"
			}`,
			responseContentType: blockedServicesIntegrationJSONContentType,
			invoke: func(ctx context.Context, client *adguard.Client) (any, error) {
				return client.GetProfile(ctx)
			},
			verify: func(t *testing.T, result any) {
				t.Helper()

				profile, ok := result.(*adguard.Profile)
				require.True(t, ok)
				assert.Equal(t, adguard.Profile{
					Name:     profileIntegrationName,
					Language: profileIntegrationLanguage,
					Theme:    profileIntegrationAutoTheme,
				}, *profile)
			},
		},
		{
			name:   "update profile",
			method: http.MethodPut,
			path:   "/api/control/profile/update",
			requestBody: `{
				"name":"dns-operator",
				"language":"` + profileIntegrationLanguage + `",
				"theme":"` + profileIntegrationDarkTheme + `"
			}`,
			invoke: func(ctx context.Context, client *adguard.Client) (any, error) {
				return nil, client.UpdateProfile(ctx, adguard.Profile{
					Name:     "dns-operator",
					Language: profileIntegrationLanguage,
					Theme:    profileIntegrationDarkTheme,
				})
			},
		},
	}
}

// profileIntegrationErrorCases returns structured profile failures.
func profileIntegrationErrorCases() []dnsIntegrationErrorCase {
	return []dnsIntegrationErrorCase{
		{
			name:      "get profile",
			operation: "get_profile",
			method:    http.MethodGet,
			path:      "/api/control/profile",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				_, err := client.GetProfile(ctx)

				return err
			},
		},
		{
			name:      "update profile",
			operation: "update_profile",
			method:    http.MethodPut,
			path:      "/api/control/profile/update",
			invoke: func(ctx context.Context, client *adguard.Client) error {
				return client.UpdateProfile(ctx, adguard.Profile{
					Name:     profileIntegrationName,
					Language: profileIntegrationLanguage,
					Theme:    profileIntegrationAutoTheme,
				})
			},
		},
	}
}
