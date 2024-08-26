// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sanitize

import (
	"github.com/terramate-io/tfjson/v2"
)

// SanitizeChange traverses a Change and replaces all values at
// the particular locations marked by BeforeSensitive AfterSensitive
// with the value supplied as replaceWith.
func SanitizeChange(result *tfjson.Change, replaceWith interface{}) {
	if result == nil {
		return
	}
	result.Before = sanitizeChangeValue(result.Before, result.BeforeSensitive, replaceWith)
	result.After = sanitizeChangeValue(result.After, result.AfterSensitive, replaceWith)
}

func sanitizeChangeValue(old, sensitive, replaceWith interface{}) interface{} {
	if old == nil {
		return nil
	}

	if shouldFilter, ok := sensitive.(bool); ok && shouldFilter {
		return replaceWith
	}

	// Only expect deep types that we would normally see in JSON, so
	// arrays and objects.
	switch values := old.(type) {
	case []interface{}:
		filterSlice, ok := sensitive.([]interface{})
		if !ok {
			break
		}
		for i := range filterSlice {
			if i >= len(values) {
				break
			}

			values[i] = sanitizeChangeValue(values[i], filterSlice[i], replaceWith)
		}
	case map[string]interface{}:
		filterMap, ok := sensitive.(map[string]interface{})
		if !ok {
			break
		}
		for filterKey := range filterMap {
			value, ok := values[filterKey]
			if !ok {
				continue
			}
			values[filterKey] = sanitizeChangeValue(value, filterMap[filterKey], replaceWith)
			sanitizeAuxiliary(filterKey, values, filterMap[filterKey], replaceWith)
		}
	}

	return old
}

var sanitizeAuxiliaryPostfix = []string{
	"_base64",
	"_base64sha1",
	"_base64sha256",
	"_base64sha512",
	"_md5",
	"_sha1",
	"_sha256",
	"_sha512",
}

func sanitizeAuxiliary(field string, values map[string]interface{}, sensitive, replaceWith interface{}) {
	if val, ok := sensitive.(bool); !ok || !val {
		return
	}

	var auxField string
	for _, aux := range sanitizeAuxiliaryPostfix {
		auxField = field + aux
		if val, ok := values[auxField]; ok && val != nil {
			values[auxField] = replaceWith
		}
	}
}
