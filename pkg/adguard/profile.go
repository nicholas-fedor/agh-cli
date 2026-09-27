// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// ProfileService exposes the current web-interface profile.
type ProfileService interface {
	GetProfile(ctx context.Context) (*Profile, error)
	UpdateProfile(ctx context.Context, profile Profile) error
}

// Profile contains the current web interface user's profile.
//
// All fields are required. Name and Language must be nonempty, and Theme must
// be "auto", "dark", or "light".
type Profile struct {
	// Name is the web interface user's name.
	Name string
	// Language is the web interface language.
	Language string
	// Theme is the web interface theme.
	Theme string
}

// profileWire mirrors the pinned profile contract.
type profileWire struct {
	Name     *string `json:"name,omitempty"`
	Language *string `json:"language,omitempty"`
	Theme    *string `json:"theme,omitempty"`
}

const (
	// OperationGetProfile identifies profile retrieval.
	operationGetProfile = "get_profile"
	// OperationUpdateProfile identifies profile updates.
	operationUpdateProfile = "update_profile"
)

var (
	// ErrRequiredProfileField identifies an absent required profile field.
	errRequiredProfileField = errors.New("required profile field is missing")
	// ErrInvalidProfileTheme identifies an unsupported profile theme.
	errInvalidProfileTheme = errors.New("invalid profile theme")
)

var _ ProfileService = (*Client)(nil)

// GetProfile retrieves the current web interface user's profile.
//
// Parameters:
//   - ctx: The request context.
//
// Returns:
//   - The complete profile, or a client error when the request fails or the
//     response omits a required field or contains an unsupported theme.
func (c *Client) GetProfile(ctx context.Context) (*Profile, error) {
	response, requestErr := c.get(ctx, operationGetProfile, "control/profile")
	if requestErr != nil {
		return nil, requestErr
	}

	var wireProfile profileWire

	requestErr = decodeGlobalJSON(operationGetProfile, http.MethodGet, response.body, &wireProfile)
	if requestErr != nil {
		return nil, requestErr
	}

	profile, err := profileFromWire(wireProfile)
	if err != nil {
		return nil, globalJSONError(operationGetProfile, http.MethodGet, err)
	}

	return profile, nil
}

// UpdateProfile updates the current web interface user's profile.
//
// Name and Language must be nonempty, and Theme must be "auto", "dark", or
// "light".
//
// Parameters:
//   - ctx: The request context.
//   - profile: The complete replacement profile.
//
// Returns:
//   - An error when validation fails or the bounded request cannot be completed.
func (c *Client) UpdateProfile(ctx context.Context, profile Profile) error {
	err := validateProfile(profile)
	if err != nil {
		return globalRequestError(operationUpdateProfile, http.MethodPut, err)
	}

	requestErr := c.postEmpty(
		ctx,
		operationUpdateProfile,
		http.MethodPut,
		"control/profile/update",
		profileWire{
			Name:     &profile.Name,
			Language: &profile.Language,
			Theme:    &profile.Theme,
		},
	)
	if requestErr != nil {
		return requestErr
	}

	return nil
}

// profileFromWire converts and validates a profile response.
//
// Parameters:
//   - wireProfile: The decoded profile wire representation.
//
// Returns:
//   - The complete domain profile, or an error when a required field is absent
//     or invalid.
func profileFromWire(wireProfile profileWire) (*Profile, error) {
	if wireProfile.Name == nil || wireProfile.Language == nil || wireProfile.Theme == nil {
		return nil, errRequiredProfileField
	}

	profile := Profile{
		Name:     *wireProfile.Name,
		Language: *wireProfile.Language,
		Theme:    *wireProfile.Theme,
	}
	err := validateProfile(profile)
	if err != nil {
		return nil, fmt.Errorf("validate profile: %w", err)
	}

	return &profile, nil
}

// validateProfile enforces required profile values and the pinned theme enumeration.
//
// Parameters:
//   - profile: The profile to validate.
//
// Returns:
//   - An error when a required value is empty or the theme is unsupported.
func validateProfile(profile Profile) error {
	if profile.Name == "" || profile.Language == "" || profile.Theme == "" {
		return errRequiredProfileField
	}

	switch profile.Theme {
	case "auto", "dark", "light":
		return nil
	default:
		return errInvalidProfileTheme
	}
}
