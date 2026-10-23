// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package connection

import (
	"fmt"
	"net/url"
	"time"

	"github.com/nicholas-fedor/agh-cli/internal/instance"
	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// RequestTimeout bounds every request a client sends to an instance.
//
// A filter-list refresh is the slowest call agh-cli makes, so the bound leaves
// room for it.
const RequestTimeout = 30 * time.Second

// defaultScheme is the transport scheme of an instance that configures none.
const defaultScheme = "https"

// New returns an AdGuard Home API client for one configured instance.
//
// The client sends basic authentication only when the instance has a username
// or a password, so an instance configured without authentication sends none.
// The configured password never appears in a returned error.
//
// Parameters:
//   - cfg: configuration of the instance to reach.
//   - options: additional client options, applied after the defaults.
//
// Returns:
//   - *adguard.Client: the client for the instance.
//   - error: a wrapped error when the client cannot be configured.
func New(cfg instance.Config, options ...adguard.Option) (*adguard.Client, error) {
	scheme := cfg.Scheme
	if scheme == "" {
		scheme = defaultScheme
	}

	baseURL := (&url.URL{Scheme: scheme, Host: cfg.Host}).String()

	clientOptions := []adguard.Option{adguard.WithRequestTimeout(RequestTimeout)}
	if cfg.Username != "" || cfg.Password != "" {
		clientOptions = append(clientOptions, adguard.WithBasicAuth(cfg.Username, cfg.Password))
	}

	client, err := adguard.NewClient(baseURL, append(clientOptions, options...)...)
	if err != nil {
		return nil, fmt.Errorf("create client for instance %q: %w", cfg.Name, err)
	}

	return client, nil
}
