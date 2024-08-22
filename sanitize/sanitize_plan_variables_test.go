// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sanitize

import (
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/terramate-io/tfjson"
)

type testVariablesCase struct {
	name            string
	old             map[string]*tfjson.PlanVariable
	configs         map[string]*tfjson.ConfigVariable
	expected        map[string]*tfjson.PlanVariable
	expectedConfigs map[string]*tfjson.ConfigVariable
}

func variablesCases() []testVariablesCase {
	return []testVariablesCase{
		{
			name: "basic",
			old: map[string]*tfjson.PlanVariable{
				"foo": &tfjson.PlanVariable{
					Value: "test-foo",
				},
				"bar": &tfjson.PlanVariable{
					Value: "test-bar",
				},
			},
			configs: map[string]*tfjson.ConfigVariable{
				"foo": &tfjson.ConfigVariable{
					Sensitive: false,
				},
				"bar": &tfjson.ConfigVariable{
					Sensitive: true,
					Default:   DefaultSensitiveValue,
				},
			},
			expected: map[string]*tfjson.PlanVariable{
				"foo": &tfjson.PlanVariable{
					Value: "test-foo",
				},
				"bar": &tfjson.PlanVariable{
					Value: DefaultSensitiveValue,
				},
			},
			expectedConfigs: map[string]*tfjson.ConfigVariable{
				"foo": &tfjson.ConfigVariable{
					Sensitive: false,
				},
				"bar": &tfjson.ConfigVariable{
					Sensitive: true,
					Default:   DefaultSensitiveValue,
				},
			},
		},
	}
}

func TestSanitizePlanVariables(t *testing.T) {
	for _, tc := range variablesCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.old
			SanitizePlanVariables(actual, tc.configs, DefaultSensitiveValue)

			if diff := cmp.Diff(tc.expected, actual); diff != "" {
				t.Errorf("SanitizePlanVariables() mismatch (-expected +actual):\n%s", diff)
			}

			if diff := cmp.Diff(tc.expectedConfigs, tc.configs); diff != "" {
				t.Errorf("SanitizePlanVariables() mismatch (-expected +actual):\n%s", diff)
			}
		})
	}
}
