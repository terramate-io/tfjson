// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sanitize

import (
	"fmt"

	"github.com/terramate-io/tfjson"
)

type SanitizeStateModuleChangeMode string

const (
	SanitizeStateModuleChangeModeBefore SanitizeStateModuleChangeMode = "before_sensitive"
	SanitizeStateModuleChangeModeAfter  SanitizeStateModuleChangeMode = "after_sensitive"
)

// SanitizeStateModule traverses a StateModule, consulting the
// supplied ResourceChange set for resources to determine whether or
// not particular values should be obfuscated.
//
// Use mode to supply the SanitizeStateModuleChangeMode that
// represents what sensitive field should be consulted to determine
// whether or not the value should be obfuscated:
//
// * SanitizeStateModuleChangeModeBefore for before_sensitive
// * SanitizeStateModuleChangeModeAfter for after_sensitive
//
// Sensitive values are replaced with the supplied replaceWith value.
func SanitizeStateModule(
	result *tfjson.StateModule,
	resourceChanges []*tfjson.ResourceChange,
	mode SanitizeStateModuleChangeMode,
	replaceWith interface{},
) {
	if result == nil {
		return
	}

	for _, v := range result.Resources {
		sanitizeStateResource(
			v,
			findResourceChange(resourceChanges, v.Address),
			mode,
			replaceWith,
		)
	}

	for _, v := range result.ChildModules {
		SanitizeStateModule(
			v,
			resourceChanges,
			mode,
			replaceWith,
		)
	}
}

func sanitizeStateResource(
	result *tfjson.StateResource,
	rc *tfjson.ResourceChange,
	mode SanitizeStateModuleChangeMode,
	replaceWith interface{},
) {
	if result == nil {
		return
	}

	var sensitive interface{}
	if rc == nil {
		sensitive = result.SensitiveValues
	} else {
		switch mode {
		case SanitizeStateModuleChangeModeBefore:
			sensitive = rc.Change.BeforeSensitive
		case SanitizeStateModuleChangeModeAfter:
			sensitive = rc.Change.AfterSensitive
		default:
			panic(fmt.Sprintf("invalid change mode %q", mode))
		}
	}

	// We can re-use sanitizeChangeValue here to do the sanitization.
	_ = sanitizeChangeValue(result.AttributeValues, sensitive, replaceWith).(map[string]interface{})
}

func findResourceChange(resourceChanges []*tfjson.ResourceChange, addr string) *tfjson.ResourceChange {
	// Linear search here, unfortunately :P
	for _, rc := range resourceChanges {
		if rc != nil && rc.Address == addr {
			return rc
		}
	}

	return nil
}

// SanitizeStateOutputs scans the supplied map of StateOutputs and
// replaces any values of outputs marked as Sensitive with the value
// supplied in replaceWith.
func SanitizeStateOutputs(result map[string]*tfjson.StateOutput, replaceWith interface{}) {
	for _, v := range result {
		if v != nil && v.Sensitive {
			v.Value = replaceWith
		}
	}
}
