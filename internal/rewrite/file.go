// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package rewrite

import (
	"fmt"
	"os"

	"go.yaml.in/yaml/v4"
)

// ParseRulesFile reads a YAML or JSON array of DNS rewrite rules.
//
// Parameters:
//   - path: path to the local rules file.
//
// Returns:
//   - []Rule: presence-aware rules decoded from the file.
//   - error: a wrapped read or parse error.
func ParseRulesFile(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read file: %w", err)
	}

	var rules []Rule

	err = yaml.Unmarshal(data, &rules)
	if err != nil {
		return nil, fmt.Errorf("parse file: %w", err)
	}

	return rules, nil
}
