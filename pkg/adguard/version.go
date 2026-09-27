// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"context"
	"errors"
	"net/http"
)

// VersionService exposes available-version information.
type VersionService interface {
	GetVersionInfo(ctx context.Context, recheckNow *bool) (*VersionInfo, error)
}

// VersionInfo describes the latest available AdGuard Home version.
//
// Disabled is required. The remaining fields are optional, with nil indicating
// an absent or null value and nonnil pointers preserving explicit false,
// zero-length, or empty values.
type VersionInfo struct {
	// Disabled reports whether version checking is disabled.
	Disabled bool
	// NewVersion contains the available version when one was reported.
	NewVersion *string
	// Announcement contains the release announcement when one was reported.
	Announcement *string
	// AnnouncementURL contains the release announcement URL when one was reported.
	AnnouncementURL *string
	// CanAutoupdate reports whether automatic updates are available when present.
	CanAutoupdate *bool
}

// versionRequestWire mirrors the pinned version lookup request contract.
type versionRequestWire struct {
	RecheckNow *bool `json:"recheck_now,omitempty"`
}

// versionInfoWire mirrors the pinned version lookup response contract.
type versionInfoWire struct {
	Disabled        *bool   `json:"disabled,omitempty"`
	NewVersion      *string `json:"new_version,omitempty"`
	Announcement    *string `json:"announcement,omitempty"`
	AnnouncementURL *string `json:"announcement_url,omitempty"`
	CanAutoupdate   *bool   `json:"can_autoupdate,omitempty"`
}

// OperationGetVersionInfo identifies version information retrieval.
const operationGetVersionInfo = "get_version_info"

// ErrRequiredVersionField identifies an absent required version field.
var errRequiredVersionField = errors.New("required version field is missing")

var _ VersionService = (*Client)(nil)

// GetVersionInfo retrieves information about the latest available version.
//
// Parameters:
//   - ctx: The request context.
//   - recheckNow: An optional request flag. Nil omits recheck_now, while a
//     nonnil pointer sends false or true explicitly.
//
// Returns:
//   - The version information, or a client error when the request fails or the
//     response omits the required Disabled field.
func (c *Client) GetVersionInfo(ctx context.Context, recheckNow *bool) (*VersionInfo, error) {
	wireInfo := versionInfoWire{
		Disabled:        nil,
		NewVersion:      nil,
		Announcement:    nil,
		AnnouncementURL: nil,
		CanAutoupdate:   nil,
	}
	requestErr := c.postJSON(
		ctx,
		operationGetVersionInfo,
		http.MethodPost,
		"control/version.json",
		versionRequestWire{RecheckNow: recheckNow},
		&wireInfo,
	)
	if requestErr != nil {
		return nil, requestErr
	}

	versionInfo, err := versionInfoFromWire(&wireInfo)
	if err != nil {
		return nil, globalJSONError(operationGetVersionInfo, http.MethodPost, err)
	}

	return versionInfo, nil
}

// versionInfoFromWire converts and validates a version information response.
//
// Parameters:
//   - wireInfo: The decoded version information wire representation.
//
// Returns:
//   - The domain version information, or an error when Disabled is absent.
func versionInfoFromWire(wireInfo *versionInfoWire) (*VersionInfo, error) {
	if wireInfo.Disabled == nil {
		return nil, errRequiredVersionField
	}

	return &VersionInfo{
		Disabled:        *wireInfo.Disabled,
		NewVersion:      wireInfo.NewVersion,
		Announcement:    wireInfo.Announcement,
		AnnouncementURL: wireInfo.AnnouncementURL,
		CanAutoupdate:   wireInfo.CanAutoupdate,
	}, nil
}
