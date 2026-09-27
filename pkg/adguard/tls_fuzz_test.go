// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

// tlsFuzzState contains the deterministic client and captured requests.
type tlsFuzzState struct {
	// captures contains requests observed by the deterministic transport.
	captures []fuzzRequestCapture
	// client performs TLS operations without external network access.
	client *Client
}

const (
	// Request fuzzing bounds derived TLS strings and names.
	tlsFuzzMaxRequestBytes = 256
	// Response fuzzing bounds TLS JSON parsing.
	tlsFuzzMaxResponseBytes = 8 << 10
)

// FuzzTLSRequestResponse verifies TLS request encoding and response contract validation.
func FuzzTLSRequestResponse(f *testing.F) {
	f.Add([]byte{}, []byte(`{}`))
	f.Add([]byte("example.org"), []byte(`{
		"enabled":true,
		"server_name":"example.org",
		"port_https":443,
		"key_type":"RSA",
		"dns_names":["example.org","www.example.org"]
	}`))
	f.Add([]byte("certificate"), []byte(`{"key_type":"ECDSA"}`))
	f.Add([]byte("invalid"), []byte(`{"key_type":"DSA"}`))
	f.Add([]byte{0xff}, []byte(`{"port_https":65536}`))
	f.Add([]byte("example.org"), []byte(`null`))
	f.Add([]byte("example.org"), []byte(`{"enabled":`))

	f.Fuzz(func(t *testing.T, requestData, responseData []byte) {
		exerciseTLSFuzz(t, requestData, responseData)
	})
}

// exerciseTLSFuzz exercises one bounded TLS request and response pair.
//
// Parameters:
//   - requestData: The fuzz-derived request bytes.
//   - responseData: The fuzz-derived response bytes.
func exerciseTLSFuzz(t *testing.T, requestData, responseData []byte) {
	t.Helper()

	requestData = boundedFuzzInput(requestData, tlsFuzzMaxRequestBytes)
	responseData = boundedFuzzInput(responseData, tlsFuzzMaxResponseBytes)

	state := newTLSFuzzClient(t, responseData)
	config := fuzzTLSConfig(requestData)

	requireTLSConfigure(t, state, config)
	requireTLSValidate(t, state, config)
	requireTLSStatus(t, state.client)
	requireTLSCaptures(t, state.captures)
}

// newTLSFuzzClient creates an offline TLS client that records every request.
//
// Parameters:
//   - responseData: The bounded JSON body returned for every operation.
//
// Returns:
//   - state: The deterministic client and its captured requests.
func newTLSFuzzClient(t *testing.T, responseData []byte) *tlsFuzzState {
	t.Helper()

	state := &tlsFuzzState{
		captures: make([]fuzzRequestCapture, 0, 3),
		client:   nil,
	}
	transport := fuzzRoundTripper(func(request *http.Request) (*http.Response, error) {
		capture, err := captureFuzzRequest(request)
		if err != nil {
			return nil, err
		}

		state.captures = append(state.captures, capture)

		return fuzzHTTPResponse(
			request,
			http.StatusOK,
			testResponseMediaType,
			responseData,
		), nil
	})

	state.client = newFuzzClient(
		t,
		transport,
		max(int64(1), int64(len(responseData))),
	)

	return state
}

// requireTLSConfigure exercises one bounded TLS configuration request.
//
// Parameters:
//   - state: The deterministic client and captured requests.
//   - config: The fuzz-derived TLS configuration.
func requireTLSConfigure(t *testing.T, state *tlsFuzzState, config TLSConfig) {
	t.Helper()

	capturesBefore := len(state.captures)
	result, err := state.client.TLSConfigure(t.Context(), config)
	kind := ErrorKindJSON
	if len(state.captures) == capturesBefore {
		kind = ErrorKindRequest
	}

	requireFuzzResult(
		t,
		result,
		err,
		kind,
		tlsConfigureOperation,
		http.MethodPost,
	)
}

// requireTLSValidate exercises one bounded TLS validation request.
//
// Parameters:
//   - state: The deterministic client and captured requests.
//   - config: The fuzz-derived TLS configuration.
func requireTLSValidate(t *testing.T, state *tlsFuzzState, config TLSConfig) {
	t.Helper()

	capturesBefore := len(state.captures)
	result, err := state.client.TLSValidate(t.Context(), config)
	kind := ErrorKindJSON
	if len(state.captures) == capturesBefore {
		kind = ErrorKindRequest
	}

	requireFuzzResult(
		t,
		result,
		err,
		kind,
		tlsValidateOperation,
		http.MethodPost,
	)
}

// requireTLSStatus verifies the TLS status result-or-error contract.
//
// Parameters:
//   - client: The deterministic AdGuard client.
func requireTLSStatus(t *testing.T, client *Client) {
	t.Helper()

	result, err := client.TLSStatus(t.Context())
	requireFuzzJSONResult(t, result, err, tlsStatusOperation, http.MethodGet)
}

// requireTLSCaptures verifies every request observed by the deterministic transport.
//
// Parameters:
//   - captures: The captured TLS requests.
func requireTLSCaptures(t *testing.T, captures []fuzzRequestCapture) {
	t.Helper()

	for _, capture := range captures {
		requireTLSCapture(t, capture)
	}
}

// requireTLSCapture verifies that one exercised TLS endpoint received a JSON request.
//
// Parameters:
//   - capture: The captured TLS request to inspect.
func requireTLSCapture(t *testing.T, capture fuzzRequestCapture) {
	t.Helper()

	switch capture.path {
	case "/api/control/tls/configure", "/api/control/tls/validate":
		assert.Equal(t, http.MethodPost, capture.method)
	case "/api/control/tls/status":
		assert.Equal(t, http.MethodGet, capture.method)
	default:
		t.Errorf("unexpected TLS fuzz path %q", capture.path)
	}

	assert.Empty(t, capture.query)
	requireFuzzJSONBody(t, capture)
}

// fuzzTLSConfig derives a bounded presence-sensitive TLS request.
//
// Parameters:
//   - data: The bounded request input.
//
// Returns:
//   - config: A TLS configuration containing fuzz-derived request and response fields.
func fuzzTLSConfig(data []byte) TLSConfig {
	if len(data) == 0 {
		return TLSConfig{}
	}

	serverName := string(data)
	certificateChain := string(data)
	privateKey := string(data)
	certificatePath := string(data)
	privateKeyPath := string(data)
	subject := string(data)
	issuer := string(data)
	notBefore := string(data)
	notAfter := string(data)
	warning := string(data)
	keyType := TLSKeyType(string(data))
	dnsNames := make([]string, 0, 2)

	dnsNames = append(dnsNames, string(data))
	if len(data) > 1 {
		dnsNames = append(dnsNames, string(data[1:]))
	}

	return TLSConfig{
		Enabled:           new(data[0]&0b01 == 0),
		ServerName:        &serverName,
		ForceHTTPS:        new(data[0]&0b10 != 0),
		PortHTTPS:         new(uint16(data[0])),
		PortDNSOverTLS:    new(uint16(data[0])),
		PortDNSOverQUIC:   new(uint16(data[0])),
		CertificateChain:  &certificateChain,
		PrivateKey:        &privateKey,
		PrivateKeySaved:   new(data[0]&0b100 != 0),
		CertificatePath:   &certificatePath,
		PrivateKeyPath:    &privateKeyPath,
		ValidCertificate:  new(data[0]&0b1000 == 0),
		ValidChain:        new(data[0]&0b10000 != 0),
		Subject:           &subject,
		Issuer:            &issuer,
		NotBefore:         &notBefore,
		NotAfter:          &notAfter,
		DNSNames:          &dnsNames,
		ValidKey:          new(data[0]&0b100000 == 0),
		KeyType:           &keyType,
		WarningValidation: &warning,
		ValidPair:         new(data[0]&0b1000000 != 0),
		ServePlainDNS:     new(data[0]&0b10000000 == 0),
	}
}
