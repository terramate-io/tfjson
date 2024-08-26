// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sanitize

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/terramate-io/tfjson"
)

type testChangeCase struct {
	name     string
	old      *tfjson.Change
	expected *tfjson.Change
}

func changeCases() []testChangeCase {
	return []testChangeCase{
		{
			name:     "nil",
			old:      nil,
			expected: nil,
		},
		{
			name: "basic",
			old: &tfjson.Change{
				Before: map[string]interface{}{
					"foo": map[string]interface{}{"a": "foo"},
					"bar": map[string]interface{}{"a": "foo"},
					"baz": map[string]interface{}{"a": "foo"},
					"qux": map[string]interface{}{
						"a": map[string]interface{}{
							"b": "foo",
						},
						"c": "bar",
					},
					"quxx": map[string]interface{}{
						"a": map[string]interface{}{
							"b": "foo",
						},
						"c": "bar",
					},
				},
				After: map[string]interface{}{
					"one":   map[string]interface{}{"x": "one"},
					"two":   map[string]interface{}{"x": "one"},
					"three": map[string]interface{}{"x": "one"},
					"four": map[string]interface{}{
						"x": map[string]interface{}{
							"y": "one",
						},
						"z": "two",
					},
					"five": map[string]interface{}{
						"x": map[string]interface{}{
							"y": "one",
						},
						"z": "two",
					},
				},
				BeforeSensitive: map[string]interface{}{
					"foo":  map[string]interface{}{},
					"bar":  true,
					"baz":  map[string]interface{}{"a": true},
					"qux":  map[string]interface{}{},
					"quxx": map[string]interface{}{"c": true},
				},
				AfterSensitive: map[string]interface{}{
					"one":   map[string]interface{}{},
					"two":   true,
					"three": map[string]interface{}{"x": true},
					"four":  map[string]interface{}{},
					"five":  map[string]interface{}{"z": true},
				},
			},
			expected: &tfjson.Change{
				Before: map[string]interface{}{
					"foo": map[string]interface{}{"a": "foo"},
					"bar": DefaultSensitiveValue,
					"baz": map[string]interface{}{"a": DefaultSensitiveValue},
					"qux": map[string]interface{}{
						"a": map[string]interface{}{
							"b": "foo",
						},
						"c": "bar",
					},
					"quxx": map[string]interface{}{
						"a": map[string]interface{}{
							"b": "foo",
						},
						"c": DefaultSensitiveValue,
					},
				},
				After: map[string]interface{}{
					"one":   map[string]interface{}{"x": "one"},
					"two":   DefaultSensitiveValue,
					"three": map[string]interface{}{"x": DefaultSensitiveValue},
					"four": map[string]interface{}{
						"x": map[string]interface{}{
							"y": "one",
						},
						"z": "two",
					},
					"five": map[string]interface{}{
						"x": map[string]interface{}{
							"y": "one",
						},
						"z": DefaultSensitiveValue,
					},
				},
				BeforeSensitive: map[string]interface{}{
					"foo":  map[string]interface{}{},
					"bar":  true,
					"baz":  map[string]interface{}{"a": true},
					"qux":  map[string]interface{}{},
					"quxx": map[string]interface{}{"c": true},
				},
				AfterSensitive: map[string]interface{}{
					"one":   map[string]interface{}{},
					"two":   true,
					"three": map[string]interface{}{"x": true},
					"four":  map[string]interface{}{},
					"five":  map[string]interface{}{"z": true},
				},
			},
		},
	}
}

func TestSanitizeChange(t *testing.T) {
	for _, tc := range changeCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.old
			SanitizeChange(actual, DefaultSensitiveValue)

			if diff := cmp.Diff(tc.expected, actual); diff != "" {
				t.Errorf("SanitizeChange() mismatch (-expected +actual):\n%s", diff)
			}
		})
	}
}
