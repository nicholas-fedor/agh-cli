// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// configFuzzTransport prevents any accidental external request from a fuzz target.
type configFuzzTransport struct{}

// configFuzzOptionValues contains bounded strings used by functional options.
type configFuzzOptionValues struct {
	// username is the bounded Basic authentication username.
	username string
	// password is the bounded Basic authentication password.
	password string
	// userAgent is the bounded User-Agent value.
	userAgent string
}

// configFuzzExpectedConfig records the final values selected by generated options.
type configFuzzExpectedConfig struct {
	// username is the expected Basic authentication username.
	username string
	// password is the expected Basic authentication password.
	password string
	// userAgent is the expected final User-Agent value.
	userAgent string
	// timeout is the expected final request timeout.
	timeout time.Duration
	// responseLimit is the expected final response-body limit.
	responseLimit int64
}

const (
	// ConfigFuzzMaxStringBytes bounds URL and option string processing per input.
	configFuzzMaxStringBytes = 4 << 10
	// ConfigFuzzMaxOptionCount bounds the functional options constructed per input.
	configFuzzMaxOptionCount = 10
	// ConfigFuzzValidValues is reused by valid and boundary option seeds.
	configFuzzValidValues = "operator:secret:valid"
)

// configFuzz option-generation masks.
const (
	configFuzzNilHTTPClientMask uint8 = 1 << iota
	configFuzzNilOptionMask
	configFuzzOverrideMask
)

// FuzzConfigBaseURL verifies bounded base URLs produce valid settings or structured errors.
func FuzzConfigBaseURL(f *testing.F) {
	seeds := []string{
		"https://example.test",
		"HTTPS://example.test/prefix/",
		"HTTPS://0//",
		"http://localhost:3000",
		"http://127.0.0.1:8080/api/",
		"http://[::1]/api",
		"https://user:password@example.test",
		"https://example.test?query=value",
		"https://example.test#fragment",
		"https:opaque",
		"http://example.test",
		"://invalid",
		"",
	}
	for _, seed := range seeds {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, rawURL string) {
		exerciseConfigFuzzBaseURL(t, rawURL)
	})
}

// exerciseConfigFuzzBaseURL checks one bounded base URL.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - rawURL: The generated base URL.
func exerciseConfigFuzzBaseURL(t *testing.T, rawURL string) {
	t.Helper()

	if len(rawURL) > configFuzzMaxStringBytes {
		rawURL = rawURL[:configFuzzMaxStringBytes]
	}

	cfg, err := newConfig(rawURL, nil)
	if err != nil {
		assert.Nil(t, cfg)

		clientErr, ok := errors.AsType[*Error](err)
		require.True(t, ok)
		assert.Equal(t, ErrorKindConfig, clientErr.Kind)
		assert.Empty(t, clientErr.Operation)
		assert.Error(t, clientErr.Err)

		return
	}

	require.NotNil(t, cfg)
	assert.Contains(t, []string{"http", "https"}, cfg.baseURL.Scheme)
	assert.NotEmpty(t, cfg.baseURL.Host)
	assert.Nil(t, cfg.baseURL.User)
	assert.Empty(t, cfg.baseURL.RawQuery)
	assert.Empty(t, cfg.baseURL.Fragment)
	assert.False(t, strings.HasSuffix(cfg.baseURL.Path, "/"))
	assert.Equal(t, defaultRequestTimeout, cfg.requestTimeout)
	assert.Equal(t, int64(defaultMaxResponseBytes), cfg.maxResponseBytes)
	assert.Equal(t, defaultUserAgent, cfg.userAgent)
	require.NotNil(t, cfg.httpClient)
	assert.NotNil(t, cfg.httpClient.CheckRedirect)
}

// FuzzConfigOptions verifies bounded option combinations preserve structured failures.
func FuzzConfigOptions(f *testing.F) {
	addConfigFuzzOptionSeeds(f)

	f.Fuzz(func(t *testing.T, values string, flags uint8, timeoutNanos int64, responseLimit int) {
		exerciseConfigFuzzOptions(t, values, flags, timeoutNanos, responseLimit)
	})
}

// addConfigFuzzOptionSeeds registers deterministic option fuzz seeds.
//
// Parameters:
//   - f: The active fuzz target.
func addConfigFuzzOptionSeeds(f *testing.F) {
	f.Helper()

	seeds := []struct {
		values        string
		flags         uint8
		timeoutNanos  int64
		responseLimit int
	}{
		{
			values:        "operator:secret:agh-cli-fuzz/1",
			flags:         0,
			timeoutNanos:  int64(time.Second),
			responseLimit: 4096,
		},
		{
			values:        "operator:secret:\x00",
			flags:         0,
			timeoutNanos:  int64(time.Second),
			responseLimit: 4096,
		},
		{
			values:        configFuzzValidValues,
			flags:         0,
			timeoutNanos:  0,
			responseLimit: 4096,
		},
		{
			values:        configFuzzValidValues,
			flags:         0,
			timeoutNanos:  int64(time.Second),
			responseLimit: 0,
		},
		{
			values:        configFuzzValidValues,
			flags:         configFuzzNilHTTPClientMask,
			timeoutNanos:  int64(time.Second),
			responseLimit: 4096,
		},
		{
			values:        configFuzzValidValues,
			flags:         configFuzzNilOptionMask,
			timeoutNanos:  int64(time.Second),
			responseLimit: 4096,
		},
		{
			values:        "ignored:ignored:invalid",
			flags:         configFuzzOverrideMask,
			timeoutNanos:  0,
			responseLimit: 0,
		},
	}
	for _, seed := range seeds {
		f.Add(seed.values, seed.flags, seed.timeoutNanos, seed.responseLimit)
	}
}

// exerciseConfigFuzzOptions checks one generated option combination.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - values: The generated combined option string.
//   - flags: The generated option masks.
//   - timeoutNanos: The generated request timeout in nanoseconds.
//   - responseLimit: The generated maximum response-body size.
func exerciseConfigFuzzOptions(
	t *testing.T,
	values string,
	flags uint8,
	timeoutNanos int64,
	responseLimit int,
) {
	t.Helper()

	options, expected := configFuzzBuildOptions(values, flags, timeoutNanos, responseLimit)
	require.LessOrEqual(t, len(options), configFuzzMaxOptionCount)

	cfg, err := newConfig("https://example.test", options)
	if err != nil {
		assert.Nil(t, cfg)

		clientErr, ok := errors.AsType[*Error](err)
		require.True(t, ok)
		assert.Equal(t, ErrorKindConfig, clientErr.Kind)
		assert.Error(t, clientErr.Err)

		return
	}

	require.NotNil(t, cfg)
	assert.True(t, cfg.basicAuth)
	assert.Equal(t, expected.username, cfg.username)
	assert.Equal(t, expected.password, cfg.password)
	assert.Equal(t, expected.userAgent, cfg.userAgent)
	assert.Equal(t, expected.timeout, cfg.requestTimeout)
	assert.Equal(t, expected.responseLimit, cfg.maxResponseBytes)
	require.NotNil(t, cfg.httpClient)
	assert.NotNil(t, cfg.httpClient.CheckRedirect)
}

// configFuzzBuildOptions converts fuzz arguments into bounded functional options.
//
// Parameters:
//   - values: The generated combined option string.
//   - flags: The generated option masks.
//   - timeoutNanos: The generated request timeout in nanoseconds.
//   - responseLimit: The generated maximum response-body size.
//
// Returns:
//   - options: At most ten deterministic options, including invalid cases.
//   - expected: The values expected when every option succeeds.
func configFuzzBuildOptions(
	values string,
	flags uint8,
	timeoutNanos int64,
	responseLimit int,
) ([]Option, configFuzzExpectedConfig) {
	valuesConfig := configFuzzSplitValues(values)
	timeout := time.Duration(timeoutNanos)
	maximumResponseSize := int64(responseLimit)
	expected := configFuzzExpectedConfig{
		username:      valuesConfig.username,
		password:      valuesConfig.password,
		userAgent:     valuesConfig.userAgent,
		timeout:       timeout,
		responseLimit: maximumResponseSize,
	}

	options := make([]Option, 0, configFuzzMaxOptionCount)

	options = append(
		options,
		WithBasicAuth(valuesConfig.username, valuesConfig.password),
		WithUserAgent(valuesConfig.userAgent),
		WithRequestTimeout(timeout),
		WithMaxResponseBodySize(maximumResponseSize),
	)

	if flags&configFuzzNilHTTPClientMask != 0 {
		options = append(options, WithHTTPClient(nil))
	} else {
		options = append(options, WithHTTPClient(&http.Client{
			Transport: configFuzzTransport{},
		}))
	}

	if flags&configFuzzOverrideMask != 0 {
		expected.username = "fuzz-user"
		expected.password = "fuzz-password"
		expected.userAgent = "agh-cli-fuzz-override/1"
		expected.timeout = time.Nanosecond
		expected.responseLimit = 1
		options = append(
			options,
			WithBasicAuth(expected.username, expected.password),
			WithUserAgent(expected.userAgent),
			WithRequestTimeout(expected.timeout),
			WithMaxResponseBodySize(expected.responseLimit),
		)
	}
	if flags&configFuzzNilOptionMask != 0 {
		options = append(options, nil)
	}

	return options, expected
}

// configFuzzSplitValues bounds and splits option strings from one fuzz input.
//
// Parameters:
//   - value: The generated combined value.
//
// Returns:
//   - values: The bounded option strings.
func configFuzzSplitValues(value string) configFuzzOptionValues {
	if len(value) > configFuzzMaxStringBytes {
		value = value[:configFuzzMaxStringBytes]
	}

	parts := strings.SplitN(value, ":", 3)
	for index := range parts {
		parts[index] = configFuzzBoundString(parts[index], configFuzzMaxStringBytes/3)
	}
	for len(parts) < 3 {
		parts = append(parts, "")
	}

	return configFuzzOptionValues{
		username:  parts[0],
		password:  parts[1],
		userAgent: parts[2],
	}
}

// configFuzzBoundString bounds a generated string without validating its contents.
//
// Parameters:
//   - value: The generated string to bound.
//   - limit: The maximum retained byte length.
//
// Returns:
//   - value: The original or prefix-bounded string.
func configFuzzBoundString(value string, limit int) string {
	if len(value) <= limit {
		return value
	}

	return value[:limit]
}

// RoundTrip rejects any request that escapes configuration-only fuzzing.
//
// Parameters:
//   - request: The unexpected outbound HTTP request.
//
// Returns:
//   - response: Always nil.
//   - err: A deterministic external-network rejection.
func (configFuzzTransport) RoundTrip(_ *http.Request) (*http.Response, error) {
	return nil, errors.New("external network disabled by configuration fuzz target")
}
