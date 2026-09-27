// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package adguard_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/nicholas-fedor/agh-cli/pkg/adguard"
)

// exampleRequest records the parts of one inbound request that the examples
// report.
//
// The examples hand every captured request to the caller over a buffered
// channel, so the reporting goroutine never shares memory with the server
// goroutine.
type exampleRequest struct {
	// accept is the Accept request header.
	accept string
	// authenticated reports whether the request carried HTTP Basic credentials.
	authenticated bool
	// body is the complete request body.
	body string
	// contentType is the Content-Type request header.
	contentType string
	// method is the request method.
	method string
	// password is the HTTP Basic password sent by the request.
	password string
	// path is the request path.
	path string
	// query is the encoded request query string.
	query string
	// userAgent is the User-Agent request header.
	userAgent string
	// username is the HTTP Basic username sent by the request.
	username string
}

// exampleRoundTripper adapts a function to [http.RoundTripper].
type exampleRoundTripper func(*http.Request) (*http.Response, error)

// Examples share fixed credentials, hosts, and wire payloads so that every
// example prints a deterministic result.
const (
	// The construction example configures this User-Agent value.
	exampleUserAgent = "example-client/1.0"
	// The authenticated example sends this HTTP Basic username.
	exampleUsername = "example-user"
	// The authenticated example sends this HTTP Basic password.
	examplePassword = "example-password"
	// The mobile configuration example requests this host.
	exampleHost = "dns.example.test"
	// The mobile configuration example sends this encrypted-DNS client identifier.
	exampleClientID = "example-device"
	// The client management example configures this client name.
	exampleClientName = "workstation"
	// The client management example configures this client address.
	exampleClientAddress = "192.0.2.77"
	// The filtering examples evaluate this host.
	exampleCheckedHost = "ads.example.test"
	// The mobile configuration example returns this media type.
	exampleMediaType = "application/x-apple-aspen-config"
	// The error example returns this non-success media type.
	exampleProblemMediaType = "application/problem+json; profile=example"
	// The timeout example bounds its request with this duration.
	exampleRequestTimeout = 20 * time.Millisecond
	// The complete status response fixture reports one optional member and
	// omits the other.
	exampleStatusBody = `{
		"dns_addresses": ["192.0.2.53"],
		"dns_port": 53,
		"http_port": 3000,
		"language": "en",
		"protection_enabled": true,
		"protection_disabled_duration": 0,
		"dhcp_available": true,
		"running": true,
		"version": "v0.107.62"
	}`
	// The filtered-host response fixture reports a blocking rule.
	exampleCheckHostBody = `{"reason":"FilteredBlackList","rule":"||ads.example.test^"}`
	// The filtered-host response fixture reports an undocumented reason.
	exampleUnknownReasonBody = `{"reason":"NotADocumentedReason"}`
	// The non-success response fixture is the body retained by a status error.
	exampleForbiddenBody = `{"message":"forbidden"}`
)

// newExampleServer starts a loopback test server and reports the request it
// receives.
//
// The returned channel holds room for exactly one request, because every
// example issues exactly one request.
//
// Parameters:
//   - respond: The handler that writes the example response.
//
// Returns:
//   - server: The running test server, which the caller must close.
//   - requests: The channel that receives the single observed request.
func newExampleServer(respond http.HandlerFunc) (*httptest.Server, <-chan exampleRequest) {
	requests := make(chan exampleRequest, 1)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)

			return
		}

		username, password, authenticated := r.BasicAuth()
		requests <- exampleRequest{
			accept:        r.Header.Get("Accept"),
			authenticated: authenticated,
			body:          string(body),
			contentType:   r.Header.Get("Content-Type"),
			method:        r.Method,
			password:      password,
			path:          r.URL.Path,
			query:         r.URL.RawQuery,
			userAgent:     r.Header.Get("User-Agent"),
			username:      username,
		}

		respond(w, r)
	}))

	return server, requests
}

// newExampleResponse builds one complete in-memory HTTP response.
//
// Parameters:
//   - body: The response body to return.
//   - contentType: The response media type to return.
//
// Returns:
//   - response: The response served by an in-memory transport.
func newExampleResponse(body, contentType string) *http.Response {
	header := http.Header{}
	header.Set("Content-Type", contentType)

	return &http.Response{
		Status:     "200 OK",
		StatusCode: http.StatusOK,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

// writeExampleJSON writes one JSON response body.
//
// Parameters:
//   - w: The response writer that sends the response.
//   - body: The JSON response body to send.
func writeExampleJSON(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "application/json")

	_, _ = fmt.Fprint(w, body)
}

// RoundTrip executes the configured round-trip function.
//
// Parameters:
//   - request: The HTTP request to pass to the configured function.
//
// Returns:
//   - response: The HTTP response returned by the configured function.
//   - err: The error returned by the configured function.
func (fn exampleRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

// ExampleNewClient_withBasicAuth demonstrates configuring a client for a local
// test server and authenticating every request with HTTP Basic credentials.
//
// Plain HTTP is accepted for loopback hosts only, so the test server address is
// the one context in which credentials may travel without TLS.
func ExampleNewClient_withBasicAuth() {
	server, requests := newExampleServer(func(w http.ResponseWriter, _ *http.Request) {
		writeExampleJSON(w, exampleStatusBody)
	})
	defer server.Close()

	client, err := adguard.NewClient(
		server.URL,
		adguard.WithBasicAuth(exampleUsername, examplePassword),
		adguard.WithUserAgent(exampleUserAgent),
	)
	if err != nil {
		fmt.Println("configure:", err)

		return
	}

	_, err = client.Status(context.Background())
	if err != nil {
		fmt.Println("status:", err)

		return
	}

	request := <-requests

	fmt.Println("method:", request.method)
	fmt.Println("authenticated:", request.authenticated)
	fmt.Println("user:", request.username)
	fmt.Println("password verified:", request.password == examplePassword)
	fmt.Println("user agent:", request.userAgent)

	// Output:
	// method: GET
	// authenticated: true
	// user: example-user
	// password verified: true
	// user agent: example-client/1.0
}

// ExampleClient_Status demonstrates decoding a server status response and the
// difference between an optional member reported as zero and an optional member
// the server omitted.
func ExampleClient_Status() {
	server, _ := newExampleServer(func(w http.ResponseWriter, _ *http.Request) {
		writeExampleJSON(w, exampleStatusBody)
	})
	defer server.Close()

	client, err := adguard.NewClient(server.URL)
	if err != nil {
		fmt.Println("configure:", err)

		return
	}

	status, err := client.Status(context.Background())
	if err != nil {
		fmt.Println("status:", err)

		return
	}

	fmt.Println("version:", status.Version)
	fmt.Println("dns port:", status.DNSPort)
	fmt.Println("protection enabled:", status.ProtectionEnabled)
	fmt.Println("dhcp available:", *status.DHCPAvailable)
	fmt.Println("disabled seconds:", *status.ProtectionDisabledDuration)
	fmt.Println("start time reported:", status.StartTime != nil)

	// Output:
	// version: v0.107.62
	// dns port: 53
	// protection enabled: true
	// dhcp available: true
	// disabled seconds: 0
	// start time reported: false
}

// ExampleClient_ClientsAdd demonstrates adding a configured client and the
// presence-sensitive request body that the client encodes for the server.
func ExampleClient_ClientsAdd() {
	server, requests := newExampleServer(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	defer server.Close()

	client, err := adguard.NewClient(server.URL)
	if err != nil {
		fmt.Println("configure:", err)

		return
	}

	err = client.ClientsAdd(context.Background(), adguard.ClientConfig{
		Name:             exampleClientName,
		IDs:              []string{exampleClientAddress},
		FilteringEnabled: true,
	})
	if err != nil {
		fmt.Println("add:", err)

		return
	}

	request := <-requests

	fmt.Println("method:", request.method)
	fmt.Println("path:", request.path)
	fmt.Println("content type:", request.contentType)
	fmt.Println("body:", request.body)

	// Output:
	// method: POST
	// path: /control/clients/add
	// content type: application/json
	// body: {"name":"workstation","ids":["192.0.2.77"],"filtering_enabled":true}
}

// ExampleClient_CheckFilteredHost demonstrates evaluating one host against the
// active filtering rules and reading the reported outcome.
func ExampleClient_CheckFilteredHost() {
	server, requests := newExampleServer(func(w http.ResponseWriter, _ *http.Request) {
		writeExampleJSON(w, exampleCheckHostBody)
	})
	defer server.Close()

	client, err := adguard.NewClient(server.URL)
	if err != nil {
		fmt.Println("configure:", err)

		return
	}

	result, err := client.CheckFilteredHost(context.Background(), adguard.CheckHostRequest{
		Name: exampleCheckedHost,
	})
	if err != nil {
		fmt.Println("check:", err)

		return
	}

	request := <-requests

	fmt.Println("query:", request.query)
	fmt.Println("reason:", *result.Reason)
	fmt.Println("rule:", *result.Rule)

	// Output:
	// query: name=ads.example.test
	// reason: FilteredBlackList
	// rule: ||ads.example.test^
}

// ExampleClient_DownloadDoH demonstrates downloading a mobile configuration as
// opaque binary data.
//
// The bytes are returned exactly as the server sent them, so the payload below
// is neither decoded as JSON nor validated as text.
func ExampleClient_DownloadDoH() {
	payload := []byte{0x00, 0x01, 0x02, 0xff, 0xfe, 'D', 'O', 'H'}

	server, requests := newExampleServer(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", exampleMediaType)
		w.WriteHeader(http.StatusOK)

		_, _ = w.Write(payload)
	})
	defer server.Close()

	client, err := adguard.NewClient(server.URL)
	if err != nil {
		fmt.Println("configure:", err)

		return
	}

	clientID := exampleClientID

	artifact, err := client.DownloadDoH(context.Background(), adguard.MobileConfigRequest{
		Host:     exampleHost,
		ClientID: &clientID,
	})
	if err != nil {
		fmt.Println("download:", err)

		return
	}

	request := <-requests

	fmt.Println("accept:", request.accept)
	fmt.Println("query:", request.query)
	fmt.Println("media type:", artifact.ContentType)
	fmt.Println("bytes:", len(artifact.Data))
	fmt.Printf("payload: % x\n", artifact.Data)

	// Output:
	// accept: application/octet-stream
	// query: client_id=example-device&host=dns.example.test
	// media type: application/x-apple-aspen-config
	// bytes: 8
	// payload: 00 01 02 ff fe 44 4f 48
}

// ExampleError demonstrates classifying client failures with [errors.AsType]
// instead of matching error text.
//
// The first call receives a non-success status, and the second receives a
// successful response that violates the filtering response contract.
func ExampleError() {
	mux := http.NewServeMux()
	mux.HandleFunc("/control/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", exampleProblemMediaType)
		w.WriteHeader(http.StatusForbidden)

		_, _ = fmt.Fprint(w, exampleForbiddenBody)
	})
	mux.HandleFunc("/control/filtering/check_host", func(w http.ResponseWriter, _ *http.Request) {
		writeExampleJSON(w, exampleUnknownReasonBody)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client, err := adguard.NewClient(server.URL)
	if err != nil {
		fmt.Println("configure:", err)

		return
	}

	_, err = client.Status(context.Background())
	if clientErr, ok := errors.AsType[*adguard.Error](err); ok {
		fmt.Println("kind:", clientErr.Kind)
		fmt.Println("status code:", clientErr.StatusCode)
		fmt.Println("body:", string(clientErr.Body))
	}

	_, err = client.CheckFilteredHost(context.Background(), adguard.CheckHostRequest{
		Name: exampleCheckedHost,
	})
	if clientErr, ok := errors.AsType[*adguard.Error](err); ok {
		fmt.Println("kind:", clientErr.Kind)
		fmt.Println("operation:", clientErr.Operation)
	}

	// Output:
	// kind: status
	// status code: 403
	// body: {"message":"forbidden"}
	// kind: json
	// operation: filtering_check_host
}

// ExampleWithHTTPClient demonstrates replacing the HTTP client so that requests
// use a caller-owned transport instead of a network connection.
func ExampleWithHTTPClient() {
	requests := make(chan *http.Request, 1)
	transport := exampleRoundTripper(func(request *http.Request) (*http.Response, error) {
		requests <- request

		return newExampleResponse(exampleStatusBody, "application/json"), nil
	})

	client, err := adguard.NewClient(
		"https://adguard.example.test",
		adguard.WithHTTPClient(&http.Client{Transport: transport}),
	)
	if err != nil {
		fmt.Println("configure:", err)

		return
	}

	status, err := client.Status(context.Background())
	if err != nil {
		fmt.Println("status:", err)

		return
	}

	request := <-requests

	fmt.Println("url:", request.URL.String())
	fmt.Println("version:", status.Version)

	// Output:
	// url: https://adguard.example.test/control/status
	// version: v0.107.62
}

// ExampleWithRequestTimeout demonstrates bounding one request with the
// configured timeout when the server never answers.
//
// The client derives a request context from the caller's context, so the
// deadline surfaces as a request failure whose cause is still matchable with
// [errors.Is].
func ExampleWithRequestTimeout() {
	server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()

	client, err := adguard.NewClient(server.URL, adguard.WithRequestTimeout(exampleRequestTimeout))
	if err != nil {
		fmt.Println("configure:", err)

		return
	}

	_, err = client.Status(context.Background())

	if clientErr, ok := errors.AsType[*adguard.Error](err); ok {
		fmt.Println("kind:", clientErr.Kind)
	}

	fmt.Println("deadline exceeded:", errors.Is(err, context.DeadlineExceeded))

	// Output:
	// kind: request
	// deadline exceeded: true
}
