// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package app

import (
	"github.com/nicholas-fedor/agh-cli/internal/instance"
)

const (
	// AlphaInstance identifies the alphabetically first shared test instance.
	alphaInstance = "alpha"
	// BadInstance identifies the shared test instance that fails an operation.
	badInstance = "bad"
	// GoodInstance identifies the shared test instance that completes an operation.
	goodInstance = "good"
	// ZuluInstance identifies the alphabetically last shared test instance.
	zuluInstance = "zulu"
	// TestHostKey is the raw instance host key.
	testHostKey = "host"
	// TestAlphaHost is the alphabetically first shared test host.
	testAlphaHost = "alpha.example.com"
	// TestBadHost is the shared test host that fails an operation.
	testBadHost = "bad.example.com"
	// TestGoodHost is the shared test host that completes an operation.
	testGoodHost = "good.example.com"
	// TestZuluHost is the alphabetically last shared test host.
	testZuluHost = "zulu.example.com"
	// TestClientName identifies the client used in app tests.
	testClientName = "desk"
	// TestClientID identifies the client used in app tests.
	testClientID = "192.0.2.10"
	// AddedClientMessage is the expected add success message.
	addedClientMessage = "Added client " + testClientName
)

// testInstances returns valid raw configurations for the shared test instances.
//
// Returns:
//   - instance.Source: instance mappings for the shared test instances.
func testInstances() instance.Source {
	return instance.Source{
		alphaInstance: map[string]any{testHostKey: testAlphaHost},
		badInstance:   map[string]any{testHostKey: testBadHost},
		goodInstance:  map[string]any{testHostKey: testGoodHost},
		zuluInstance:  map[string]any{testHostKey: testZuluHost},
	}
}
