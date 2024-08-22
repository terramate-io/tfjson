// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sanitize

import (
	"github.com/terramate-io/tfjson"
)

// SanitizePlanVariables traverses a map of PlanVariable and replaces
// any sensitive values with the value supplied in replaceWith.
// configs should be the map of ConfigVariables from the root module
// (so Plan.Config.RootModule.Variables).
func SanitizePlanVariables(
	result map[string]*tfjson.PlanVariable,
	configs map[string]*tfjson.ConfigVariable,
	replaceWith interface{},
) {
	for k, v := range result {
		sanitizeVariable(v, configs[k], replaceWith)
	}
}

func sanitizeVariable(
	result *tfjson.PlanVariable,
	config *tfjson.ConfigVariable,
	replaceWith interface{},
) {
	if result == nil || config == nil {
		return
	}

	if config.Sensitive {
		result.Value = replaceWith
	}
}
