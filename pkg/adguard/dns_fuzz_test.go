// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fuzzRequestTransport returns deterministic local responses without network access.
type fuzzRequestTransport struct{}

const (
	// FuzzResponseMaxBytes bounds each generated JSON response.
	fuzzResponseMaxBytes = 16 << 10
	// FuzzRequestMaxBytes bounds encoded request fuzz input.
	fuzzRequestMaxBytes = fuzzRequestControlBytes +
		fuzzRequestStringCount*fuzzRequestStringBytes +
		fuzzRequestNumericCount*fuzzRequestNumericBytes
	// FuzzRequestControlBytes bounds presence and flag bytes.
	fuzzRequestControlBytes = 8
	// FuzzRequestStringBytes bounds each encoded request string.
	fuzzRequestStringBytes = 32
	// FuzzRequestStringCount is the number of encoded request strings.
	fuzzRequestStringCount = 11
	// FuzzRequestNumericBytes is the encoded width of each numeric value.
	fuzzRequestNumericBytes = 8
	// FuzzRequestNumericCount is the number of encoded numeric values.
	fuzzRequestNumericCount = 9
	// FuzzRequestStringsOffset is the first encoded string byte.
	fuzzRequestStringsOffset = fuzzRequestControlBytes
	// FuzzRequestNumericOffset is the first encoded numeric byte.
	fuzzRequestNumericOffset = fuzzRequestStringsOffset +
		fuzzRequestStringCount*fuzzRequestStringBytes
	// FuzzSeedProfileName is the deterministic profile seed name.
	fuzzSeedProfileName = "operator"
	// FuzzSeedResolver is the deterministic upstream seed value.
	fuzzSeedResolver = "1.1.1.1"
	// FuzzSeedCustomIP is the deterministic EDNS seed value.
	fuzzSeedCustomIP = "192.0.2.1"
	// FuzzOKStatus is the deterministic local response status.
	fuzzOKStatus = "200 OK"
	// GlobalFuzzDuplicateMemberJSON covers duplicate object members.
	globalFuzzDuplicateMemberJSON = `{"running":true,"running":false}`
	// TestNullJSON covers a top-level null response.
	testNullJSON = "null"
)

// Presence masks select optional scalar fields in DNS configuration requests.
const (
	dnsFuzzPresentProtectionEnabled uint32 = 1 << iota
	dnsFuzzPresentRateLimit
	dnsFuzzPresentSubnetV4
	dnsFuzzPresentSubnetV6
	dnsFuzzPresentBlockingMode
	dnsFuzzPresentBlockingIPv4
	dnsFuzzPresentBlockingIPv6
	dnsFuzzPresentResponseTTL
	dnsFuzzPresentProtectionDisabledUntil
	dnsFuzzPresentEDNSCSEnabled
	dnsFuzzPresentEDNSCSUseCustom
	dnsFuzzPresentEDNSCSCustomIP
	dnsFuzzPresentDisableIPv6
	dnsFuzzPresentDNSSEC
	dnsFuzzPresentCacheSize
	dnsFuzzPresentCacheTTLMin
	dnsFuzzPresentCacheTTLMax
	dnsFuzzPresentCacheEnabled
	dnsFuzzPresentCacheOptimistic
	dnsFuzzPresentUpstreamMode
	dnsFuzzPresentPrivatePTR
	dnsFuzzPresentResolveClients
	dnsFuzzPresentUpstreamTimeout
	dnsFuzzPresentUpstreamDNSFile
)

// List masks select omitted DNS and upstream request lists.
const (
	dnsFuzzOmitBootstrap uint8 = 1 << iota
	dnsFuzzOmitUpstream
	dnsFuzzOmitFallback
	dnsFuzzOmitPrivateUpstream
	dnsFuzzOmitRateLimitWhitelist
	dnsFuzzOmitLocalPTRUpstreams
)

// Request flags select optional protection duration and version request values.
const (
	fuzzRequestOmitDuration uint8 = 1 << iota
	fuzzRequestOmitRecheckNow
)

// Boolean masks select explicit boolean request values.
const (
	fuzzRequestProtectionEnabledBit uint16 = 1 << iota
	fuzzRequestEDNSCSEnabledBit
	fuzzRequestEDNSCSUseCustomBit
	fuzzRequestDisableIPv6Bit
	fuzzRequestDNSSECEnabledBit
	fuzzRequestCacheEnabledBit
	fuzzRequestCacheOptimisticBit
	fuzzRequestPrivatePTRBit
	fuzzRequestResolveClientsBit
	fuzzRequestRecheckNowBit
)

// String indexes identify fields in the bounded request encoding.
const (
	fuzzRequestProfileName = iota
	fuzzRequestLanguage
	fuzzRequestTheme
	fuzzRequestBlockingMode
	fuzzRequestUpstreamMode
	fuzzRequestUpstreamDNSFile
	fuzzRequestProtectionDisabledUntil
	fuzzRequestBlockingIPv4
	fuzzRequestBlockingIPv6
	fuzzRequestEDNSCSCustomIP
	fuzzRequestListValue
)

// Numeric indexes identify fields in the bounded request encoding.
const (
	fuzzRequestRateLimit = iota
	fuzzRequestSubnetV4
	fuzzRequestSubnetV6
	fuzzRequestResponseTTL
	fuzzRequestCacheSize
	fuzzRequestCacheTTLMin
	fuzzRequestCacheTTLMax
	fuzzRequestUpstreamTimeout
	fuzzRequestProtectionDuration
)

// FuzzDNSResponseBodies verifies the DNS response schemas stay structured and bounded.
func FuzzDNSResponseBodies(f *testing.F) {
	addFuzzResponseSeeds(f)

	f.Fuzz(func(t *testing.T, body []byte) {
		if len(body) > fuzzResponseMaxBytes {
			body = body[:fuzzResponseMaxBytes]
		}

		exerciseDNSResponseFuzz(t, body)
		exerciseUpstreamResponseFuzz(t, body)
	})
}

// FuzzDNSRequestValues verifies every DNS request value reaches a local transport safely.
func FuzzDNSRequestValues(f *testing.F) {
	addFuzzRequestSeeds(f)

	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > fuzzRequestMaxBytes {
			data = data[:fuzzRequestMaxBytes]
		}

		exerciseDNSRequestFuzz(t, data)
	})
}

// addFuzzResponseSeeds registers deterministic response fixtures.
//
// Parameters:
//   - f: The active fuzz target.
func addFuzzResponseSeeds(f *testing.F) {
	f.Helper()

	seeds := []string{
		`{
			"bootstrap_dns":["1.1.1.1"],
			"protection_enabled":true,
			"cache_ttl_max":3600,
			"name":"operator",
			"language":"en",
			"theme":"dark",
			"disabled":false,
			"new_version":"v0.108.0",
			"announcement":null,
			"can_autoupdate":false
		}`,
		`{"name":"operator","language":"en","theme":"auto"}`,
		`{"disabled":true,"new_version":null,"announcement_url":""}`,
		`{"1.1.1.1":"OK","tls://dns.example":"timeout"}`,
		`{"bootstrap_dns":[],"protection_disabled_until":null,"default_local_ptr_upstreams":[]}`,
		globalFuzzDuplicateMemberJSON,
		testNullJSON,
		`[]`,
		`{`,
		``,
	}
	for _, seed := range seeds {
		f.Add([]byte(seed))
	}
}

// addFuzzRequestSeeds registers deterministic request-value fixtures.
//
// Parameters:
//   - f: The active fuzz target.
func addFuzzRequestSeeds(f *testing.F) {
	f.Helper()

	f.Add(fuzzRequestSeed(0))
	f.Add(fuzzRequestSeed(1))
	f.Add(fuzzRequestSeed(2))
}

// exerciseDNSResponseFuzz validates DNS response decoding and conversion.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - body: The bounded JSON response body.
func exerciseDNSResponseFuzz(t *testing.T, body []byte) {
	t.Helper()

	var wire dnsConfigWire

	err := decodeGlobalJSON(operationDNSInfo, http.MethodGet, body, &wire)
	if err != nil {
		assertFuzzResponseError(t, err, operationDNSInfo, http.MethodGet)

		return
	}

	config := dnsConfigFromWire(wire)
	require.NotNil(t, config)

	validationErr := validateDNSConfig(config)
	if validationErr != nil {
		assertFuzzResponseError(
			t,
			globalJSONError(operationDNSInfo, http.MethodGet, validationErr),
			operationDNSInfo,
			http.MethodGet,
		)
	}
}

// exerciseUpstreamResponseFuzz validates upstream result map decoding.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - body: The bounded JSON response body.
func exerciseUpstreamResponseFuzz(t *testing.T, body []byte) {
	t.Helper()

	results := map[string]string{}
	err := decodeGlobalJSON(
		operationTestUpstream,
		http.MethodPost,
		body,
		&results,
	)
	if err != nil {
		assertFuzzResponseError(t, err, operationTestUpstream, http.MethodPost)

		return
	}

	assert.NotNil(t, results)
}

// exerciseDNSRequestFuzz exercises each DNS request using local responses.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - data: The bounded encoded request values.
func exerciseDNSRequestFuzz(t *testing.T, data []byte) {
	t.Helper()

	client := newFuzzRequestClient(t)
	config := buildDNSFuzzConfig(data)

	err := client.SetDNSConfig(t.Context(), config)
	assertFuzzRequestError(t, err, operationDNSConfig, http.MethodPost)

	dnsInfo, err := client.DNSInfo(t.Context())
	require.NoError(t, err)
	require.NotNil(t, dnsInfo)

	upstreamConfig := UpstreamConfig{
		BootstrapDNS:    fuzzRequestList(data, dnsFuzzOmitBootstrap),
		UpstreamDNS:     fuzzRequestList(data, dnsFuzzOmitUpstream),
		FallbackDNS:     fuzzRequestList(data, dnsFuzzOmitFallback),
		PrivateUpstream: fuzzRequestList(data, dnsFuzzOmitPrivateUpstream),
	}
	results, err := client.TestUpstreamDNS(t.Context(), upstreamConfig)
	assertFuzzRequestError(t, err, operationTestUpstream, http.MethodPost)

	if err == nil {
		assert.NotNil(t, results)
	}
}

// buildDNSFuzzConfig creates a bounded DNS request from encoded values.
//
// Parameters:
//   - data: The bounded encoded request values.
//
// Returns:
//   - config: A DNS configuration with generated list and scalar presence.
func buildDNSFuzzConfig(data []byte) *DNSConfig {
	presence := fuzzRequestPresence(data)
	listValue := fuzzRequestString(data, fuzzRequestListValue)
	config := &DNSConfig{
		BootstrapDNS:             fuzzRequestList(data, dnsFuzzOmitBootstrap),
		UpstreamDNS:              fuzzRequestList(data, dnsFuzzOmitUpstream),
		FallbackDNS:              fuzzRequestList(data, dnsFuzzOmitFallback),
		RateLimitWhitelist:       fuzzRequestList(data, dnsFuzzOmitRateLimitWhitelist),
		LocalPTRUpstreams:        fuzzRequestList(data, dnsFuzzOmitLocalPTRUpstreams),
		DefaultLocalPTRUpstreams: []string{listValue},
	}
	setDNSFuzzNetworkFields(config, data, presence)
	setDNSFuzzBlockingFields(config, data, presence)
	setDNSFuzzCacheFields(config, data, presence)

	return config
}

// setDNSFuzzNetworkFields sets DNS request network fields.
//
// Parameters:
//   - config: The DNS configuration to populate.
//   - data: The bounded encoded request values.
//   - presence: The generated optional-field mask.
func setDNSFuzzNetworkFields(
	config *DNSConfig,
	data []byte,
	presence uint32,
) {
	config.UpstreamDNSFile = fuzzRequestOptional(
		presence,
		dnsFuzzPresentUpstreamDNSFile,
		fuzzRequestString(data, fuzzRequestUpstreamDNSFile),
	)
	config.UpstreamMode = fuzzRequestOptional(
		presence,
		dnsFuzzPresentUpstreamMode,
		fuzzRequestString(data, fuzzRequestUpstreamMode),
	)
	config.UsePrivatePTRResolvers = fuzzRequestOptional(
		presence,
		dnsFuzzPresentPrivatePTR,
		fuzzRequestBoolean(data, fuzzRequestPrivatePTRBit),
	)
	config.ResolveClients = fuzzRequestOptional(
		presence,
		dnsFuzzPresentResolveClients,
		fuzzRequestBoolean(data, fuzzRequestResolveClientsBit),
	)
	config.UpstreamTimeout = fuzzRequestOptional(
		presence,
		dnsFuzzPresentUpstreamTimeout,
		fuzzRequestNumber(data, fuzzRequestUpstreamTimeout),
	)
}

// setDNSFuzzBlockingFields sets DNS request blocking fields.
//
// Parameters:
//   - config: The DNS configuration to populate.
//   - data: The bounded encoded request values.
//   - presence: The generated optional-field mask.
func setDNSFuzzBlockingFields(
	config *DNSConfig,
	data []byte,
	presence uint32,
) {
	config.ProtectionEnabled = fuzzRequestOptional(
		presence,
		dnsFuzzPresentProtectionEnabled,
		fuzzRequestBoolean(data, fuzzRequestProtectionEnabledBit),
	)
	config.RateLimit = fuzzRequestOptional(
		presence,
		dnsFuzzPresentRateLimit,
		fuzzRequestNumber(data, fuzzRequestRateLimit),
	)
	config.RateLimitSubnetLengthIPv4 = fuzzRequestOptional(
		presence,
		dnsFuzzPresentSubnetV4,
		int(fuzzRequestNumber(data, fuzzRequestSubnetV4)),
	)
	config.RateLimitSubnetLengthIPv6 = fuzzRequestOptional(
		presence,
		dnsFuzzPresentSubnetV6,
		int(fuzzRequestNumber(data, fuzzRequestSubnetV6)),
	)
	config.BlockingMode = fuzzRequestOptional(
		presence,
		dnsFuzzPresentBlockingMode,
		fuzzRequestString(data, fuzzRequestBlockingMode),
	)
	config.BlockingIPv4 = fuzzRequestOptional(
		presence,
		dnsFuzzPresentBlockingIPv4,
		fuzzRequestString(data, fuzzRequestBlockingIPv4),
	)
	config.BlockingIPv6 = fuzzRequestOptional(
		presence,
		dnsFuzzPresentBlockingIPv6,
		fuzzRequestString(data, fuzzRequestBlockingIPv6),
	)
	config.BlockedResponseTTL = fuzzRequestOptional(
		presence,
		dnsFuzzPresentResponseTTL,
		fuzzRequestNumber(data, fuzzRequestResponseTTL),
	)
	config.ProtectionDisabledUntil = fuzzRequestOptional(
		presence,
		dnsFuzzPresentProtectionDisabledUntil,
		fuzzRequestString(data, fuzzRequestProtectionDisabledUntil),
	)
}

// setDNSFuzzCacheFields sets DNS request cache and EDNS fields.
//
// Parameters:
//   - config: The DNS configuration to populate.
//   - data: The bounded encoded request values.
//   - presence: The generated optional-field mask.
func setDNSFuzzCacheFields(
	config *DNSConfig,
	data []byte,
	presence uint32,
) {
	config.EDNSCSEnabled = fuzzRequestOptional(
		presence,
		dnsFuzzPresentEDNSCSEnabled,
		fuzzRequestBoolean(data, fuzzRequestEDNSCSEnabledBit),
	)
	config.EDNSCSUseCustom = fuzzRequestOptional(
		presence,
		dnsFuzzPresentEDNSCSUseCustom,
		fuzzRequestBoolean(data, fuzzRequestEDNSCSUseCustomBit),
	)
	config.EDNSCSCustomIP = fuzzRequestOptional(
		presence,
		dnsFuzzPresentEDNSCSCustomIP,
		fuzzRequestString(data, fuzzRequestEDNSCSCustomIP),
	)
	config.DisableIPv6 = fuzzRequestOptional(
		presence,
		dnsFuzzPresentDisableIPv6,
		fuzzRequestBoolean(data, fuzzRequestDisableIPv6Bit),
	)
	config.DNSSECEnabled = fuzzRequestOptional(
		presence,
		dnsFuzzPresentDNSSEC,
		fuzzRequestBoolean(data, fuzzRequestDNSSECEnabledBit),
	)
	config.CacheSize = fuzzRequestOptional(
		presence,
		dnsFuzzPresentCacheSize,
		fuzzRequestNumber(data, fuzzRequestCacheSize),
	)
	config.CacheTTLMin = fuzzRequestOptional(
		presence,
		dnsFuzzPresentCacheTTLMin,
		fuzzRequestNumber(data, fuzzRequestCacheTTLMin),
	)
	config.CacheTTLMax = fuzzRequestOptional(
		presence,
		dnsFuzzPresentCacheTTLMax,
		fuzzRequestNumber(data, fuzzRequestCacheTTLMax),
	)
	config.CacheEnabled = fuzzRequestOptional(
		presence,
		dnsFuzzPresentCacheEnabled,
		fuzzRequestBoolean(data, fuzzRequestCacheEnabledBit),
	)
	config.CacheOptimistic = fuzzRequestOptional(
		presence,
		dnsFuzzPresentCacheOptimistic,
		fuzzRequestBoolean(data, fuzzRequestCacheOptimisticBit),
	)
}

// assertFuzzResponseError verifies a response error's complete structure.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The structured response error.
//   - operation: The expected operation identifier.
//   - method: The expected HTTP method.
func assertFuzzResponseError(
	t *testing.T,
	err error,
	operation string,
	method string,
) {
	t.Helper()

	require.Error(t, err)

	clientErr, ok := errors.AsType[*Error](err)
	require.True(t, ok)
	assert.Equal(t, ErrorKindJSON, clientErr.Kind)
	assert.Equal(t, operation, clientErr.Operation)
	assert.Equal(t, method, clientErr.Method)
	assert.Zero(t, clientErr.StatusCode)
	assert.Empty(t, clientErr.Body)
	assert.Error(t, clientErr.Err)
}

// assertFuzzRequestError verifies any request failure remains structured.
//
// Parameters:
//   - t: The active fuzz subtest.
//   - err: The error returned by a request.
//   - operation: The expected operation identifier.
//   - method: The expected HTTP method.
func assertFuzzRequestError(
	t *testing.T,
	err error,
	operation string,
	method string,
) {
	t.Helper()

	if err == nil {
		return
	}

	clientErr, ok := errors.AsType[*Error](err)
	require.True(t, ok)
	assert.Equal(t, ErrorKindRequest, clientErr.Kind)
	assert.Equal(t, operation, clientErr.Operation)
	assert.Equal(t, method, clientErr.Method)
	assert.Error(t, clientErr.Err)
}

// fuzzRequestSeed builds one deterministic encoded request input.
//
// Parameters:
//   - selector: The fixture variant selector.
//
// Returns:
//   - data: A fixed-size request input.
func fuzzRequestSeed(selector byte) []byte {
	data := make([]byte, 0, fuzzRequestMaxBytes)
	for range fuzzRequestMaxBytes {
		data = append(data, 0)
	}

	data[0] = 0xff
	data[1] = 0xff
	data[2] = 0xff
	data[5] = 0xff
	data[6] = 0x03
	fuzzRequestWriteSeedString(data, fuzzRequestProfileName, fuzzSeedProfileName)
	fuzzRequestWriteSeedString(data, fuzzRequestLanguage, "en")
	fuzzRequestWriteSeedString(data, fuzzRequestTheme, "dark")
	fuzzRequestWriteSeedString(data, fuzzRequestBlockingMode, "default")
	fuzzRequestWriteSeedString(data, fuzzRequestUpstreamMode, "parallel")
	fuzzRequestWriteSeedString(data, fuzzRequestUpstreamDNSFile, "upstreams.conf")
	fuzzRequestWriteSeedString(data, fuzzRequestBlockingIPv4, "0.0.0.0")
	fuzzRequestWriteSeedString(data, fuzzRequestBlockingIPv6, "::")
	fuzzRequestWriteSeedString(data, fuzzRequestEDNSCSCustomIP, fuzzSeedCustomIP)
	fuzzRequestWriteSeedString(data, fuzzRequestListValue, fuzzSeedResolver)
	fuzzRequestWriteSeedNumber(data, fuzzRequestRateLimit, 20)
	fuzzRequestWriteSeedNumber(data, fuzzRequestSubnetV4, 24)
	fuzzRequestWriteSeedNumber(data, fuzzRequestSubnetV6, 64)
	fuzzRequestWriteSeedNumber(data, fuzzRequestResponseTTL, 60)
	fuzzRequestWriteSeedNumber(data, fuzzRequestCacheSize, 1024)
	fuzzRequestWriteSeedNumber(data, fuzzRequestCacheTTLMax, 3600)
	fuzzRequestWriteSeedNumber(data, fuzzRequestUpstreamTimeout, 1000)
	fuzzRequestWriteSeedNumber(data, fuzzRequestProtectionDuration, 900)

	switch selector {
	case 1:
		data[0] = 0
		data[1] = 0
		data[2] = 0
		data[3] = dnsFuzzOmitBootstrap | dnsFuzzOmitUpstream
		data[4] = fuzzRequestOmitDuration | fuzzRequestOmitRecheckNow
		fuzzRequestWriteSeedString(data, fuzzRequestTheme, "neon")
		fuzzRequestWriteSeedString(data, fuzzRequestBlockingMode, "unsupported")
		fuzzRequestWriteSeedNumber(data, fuzzRequestResponseTTL, ^uint64(0))
		fuzzRequestWriteSeedNumber(data, fuzzRequestUpstreamTimeout, 0)
	case 2:
		data[3] = dnsFuzzOmitFallback | dnsFuzzOmitPrivateUpstream
		data[4] = fuzzRequestOmitRecheckNow
		fuzzRequestWriteSeedString(data, fuzzRequestTheme, "light")
		fuzzRequestWriteSeedString(data, fuzzRequestBlockingMode, "custom_ip")
		fuzzRequestWriteSeedString(data, fuzzRequestUpstreamMode, "load_balance")
		fuzzRequestWriteSeedNumber(data, fuzzRequestUpstreamTimeout, 1)
	default:
	}

	return data
}

// fuzzRequestWriteSeedString writes one fixed-width seed string.
//
// Parameters:
//   - data: The encoded seed input.
//   - index: The string field index.
//   - value: The string value to write.
func fuzzRequestWriteSeedString(data []byte, index int, value string) {
	offset := fuzzRequestStringsOffset + index*fuzzRequestStringBytes
	copy(data[offset:offset+fuzzRequestStringBytes], value)
}

// fuzzRequestWriteSeedNumber writes one fixed-width seed number.
//
// Parameters:
//   - data: The encoded seed input.
//   - index: The numeric field index.
//   - value: The numeric value to write.
func fuzzRequestWriteSeedNumber(data []byte, index int, value uint64) {
	offset := fuzzRequestNumericOffset + index*fuzzRequestNumericBytes
	binary.LittleEndian.PutUint64(data[offset:offset+fuzzRequestNumericBytes], value)
}

// fuzzRequestOptional creates a bounded optional request scalar.
//
// Parameters:
//   - presence: The generated optional-field mask.
//   - bit: The bit selecting one optional field.
//   - value: The generated scalar value.
//
// Returns:
//   - Nil when omitted, or a pointer to value when present.
func fuzzRequestOptional[T any](presence, bit uint32, value T) *T {
	if presence&bit == 0 {
		return nil
	}

	return new(value)
}

// fuzzRequestList creates a bounded present or omitted string list.
//
// Parameters:
//   - data: The bounded encoded request values.
//   - omittedMask: The bit selecting this list's omission.
//
// Returns:
//   - Nil when omitted, or a bounded nonnil list.
func fuzzRequestList(data []byte, omittedMask uint8) []string {
	if len(data) > fuzzRequestControlBytes && data[3]&omittedMask != 0 {
		return nil
	}

	value := fuzzRequestString(data, fuzzRequestListValue)
	if value == "" {
		return []string{}
	}

	values := make([]string, 0, 2)

	values = append(values, value, value)

	return values
}

// fuzzRequestString reads one bounded encoded request string.
//
// Parameters:
//   - data: The bounded encoded request values.
//   - index: The string field index.
//
// Returns:
//   - The decoded string, or an empty string when the field is absent.
func fuzzRequestString(data []byte, index int) string {
	offset := fuzzRequestStringsOffset + index*fuzzRequestStringBytes
	if offset >= len(data) {
		return ""
	}

	end := min(offset+fuzzRequestStringBytes, len(data))

	return string(data[offset:end])
}

// fuzzRequestNumber reads one bounded encoded numeric value.
//
// Parameters:
//   - data: The bounded encoded request values.
//   - index: The numeric field index.
//
// Returns:
//   - The decoded value, or zero when the field is absent.
func fuzzRequestNumber(data []byte, index int) int64 {
	offset := fuzzRequestNumericOffset + index*fuzzRequestNumericBytes
	if len(data) < offset+fuzzRequestNumericBytes {
		return 0
	}

	return int64(binary.LittleEndian.Uint64(data[offset : offset+fuzzRequestNumericBytes]))
}

// fuzzRequestPresence reads the generated optional-field mask.
//
// Parameters:
//   - data: The bounded encoded request values.
//
// Returns:
//   - The three-byte optional-field mask.
func fuzzRequestPresence(data []byte) uint32 {
	if len(data) < 3 {
		return 0
	}

	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16
}

// fuzzRequestFlag reads one generated request flag.
//
// Parameters:
//   - data: The bounded encoded request values.
//   - flag: The flag bit to inspect.
//
// Returns:
//   - The selected flag byte.
func fuzzRequestFlag(data []byte, flag uint8) uint8 {
	if len(data) <= 4 {
		return 0
	}

	return data[4] & flag
}

// fuzzRequestBoolean reads one generated boolean request value.
//
// Parameters:
//   - data: The bounded encoded request values.
//   - bit: The boolean bit to inspect.
//
// Returns:
//   - The decoded boolean value.
func fuzzRequestBoolean(data []byte, bit uint16) bool {
	if len(data) < 7 {
		return false
	}

	flags := uint16(data[5]) | uint16(data[6])<<8

	return flags&(1<<bit) != 0
}

// newFuzzRequestClient creates a client whose transport is fully local.
//
// Parameters:
//   - t: The active fuzz subtest.
//
// Returns:
//   - client: A configured client that cannot use the network.
func newFuzzRequestClient(t *testing.T) *Client {
	t.Helper()

	client, err := NewClient(
		"https://example.test",
		WithHTTPClient(&http.Client{Transport: fuzzRequestTransport{}}),
		WithMaxResponseBodySize(4096),
	)
	require.NoError(t, err)
	require.NotNil(t, client)

	return client
}

// RoundTrip returns deterministic JSON for request fuzzing.
//
// Parameters:
//   - request: The locally constructed HTTP request.
//
// Returns:
//   - response: A complete in-memory HTTP response.
//   - err: Always nil.
func (fuzzRequestTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	body := `{}`
	if request != nil && request.URL != nil {
		switch request.URL.Path {
		case "/control/profile":
			body = `{"name":"fuzz-user","language":"en","theme":"dark"}`
		case "/control/version.json":
			body = `{"disabled":false,"new_version":"v0.108.0","can_autoupdate":true}`
		case "/control/test_upstream_dns":
			body = `{"1.1.1.1":"OK"}`
		default:
			body = `{}`
		}
	}

	return &http.Response{
		Status:        fuzzOKStatus,
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": {jsonContentType}},
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}, nil
}
