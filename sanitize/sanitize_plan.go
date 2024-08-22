// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sanitize

import (
	"errors"

	"github.com/terramate-io/tfjson"
)

const DefaultSensitiveValue = "REDACTED_SENSITIVE"

var NilPlanError = errors.New("nil plan supplied")

// SanitizePlan sanitizes the entirety of a Plan, replacing sensitive
// values with the default value in DefaultSensitiveValue.
//
// See SanitizePlanWithValue for full detail on the where replacement
// takes place.
func SanitizePlan(result *tfjson.Plan) error {
	return SanitizePlanWithValue(result, DefaultSensitiveValue)
}

// SanitizePlanWithValue sanitizes the entirety of a Plan to the best
// of its ability, depending on the provided metadata on sensitive
// values. These are found in:
//
// * ResourceChanges: Sanitized based on BeforeSensitive and
// AfterSensitive fields.
//
// * Variables: Based on variable config data found in the root
// module of the Config.
//
// * PlannedValues: Sanitized based on the values found in
// AfterSensitive in ResourceChanges. Outputs are sanitized
// according to the appropriate sensitivity flags provided for the
// output.
//
// * PriorState: Sanitized based on the values found in
// BeforeSensitive in ResourceChanges. Outputs are sanitized according
// to the appropriate sensitivity flags provided for the output.
//
// * OutputChanges: Sanitized based on the values found in
// BeforeSensitive and AfterSensitive. This generally means that
// any sensitive output will have OutputChange fully obfuscated as
// the BeforeSensitive and AfterSensitive in outputs are opaquely the
// same.
//
// Sensitive values are replaced with the value supplied with replaceWith.
func SanitizePlanWithValue(result *tfjson.Plan, replaceWith interface{}) error {
	if result == nil {
		return NilPlanError
	}

	// Sanitize ResourceChanges
	for _, v := range result.ResourceChanges {
		SanitizeChange(v.Change, replaceWith)
	}

	// Sanitize ResourceDrifts
	for _, v := range result.ResourceDrift {
		SanitizeChange(v.Change, replaceWith)
	}

	// Sanitize PlannedValues
	if result.PlannedValues != nil {
		SanitizeStateModule(
			result.PlannedValues.RootModule,
			result.ResourceChanges,
			SanitizeStateModuleChangeModeAfter,
			replaceWith)

		SanitizeStateOutputs(result.PlannedValues.Outputs, replaceWith)
	}

	// Sanitize PriorState
	if result.PriorState != nil && result.PriorState.Values != nil {
		SanitizeStateModule(
			result.PriorState.Values.RootModule,
			result.ResourceChanges,
			SanitizeStateModuleChangeModeBefore,
			replaceWith)

		SanitizeStateOutputs(result.PriorState.Values.Outputs, replaceWith)
	}

	// Sanitize OutputChanges
	for _, v := range result.OutputChanges {
		SanitizeChange(v, replaceWith)
	}

	if result.Config != nil {
		// Sanitize ProviderConfigs
		SanitizeProviderConfigs(result.Config.ProviderConfigs, replaceWith)

		if result.Config.RootModule != nil {
			// Sanitize RootModule recursively into module calls and child_modules
			sanitizeModuleConfig(result.Config.RootModule, replaceWith)

			// Sanitize Variables
			SanitizePlanVariables(result.Variables, result.Config.RootModule.Variables, replaceWith)
		}
	}
	return nil
}
