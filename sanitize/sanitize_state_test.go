// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sanitize

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/zclconf/go-cty-debug/ctydebug"

	"github.com/terramate-io/tfjson/v2"
)

type testStateCase struct {
	name            string
	old             *tfjson.StateModule
	resourceChanges []*tfjson.ResourceChange
	mode            SanitizeStateModuleChangeMode
	expected        *tfjson.StateModule
}

func stateCases() []testStateCase {
	return []testStateCase{
		{
			name:            "nil",
			old:             nil,
			resourceChanges: nil,
			mode:            "",
			expected:        nil,
		},
		{
			name: "before",
			old: &tfjson.StateModule{
				Resources: []*tfjson.StateResource{
					{
						Address: "null_resource.foo",
						AttributeValues: map[string]interface{}{
							"foo": "bar",
							"baz": "qux",
						},
					},
				},
				Address: "",
				ChildModules: []*tfjson.StateModule{
					&tfjson.StateModule{
						Resources: []*tfjson.StateResource{
							{
								Address: "module.foo.null_resource.bar",
								AttributeValues: map[string]interface{}{
									"a": "b",
									"c": "d",
								},
							},
						},
						Address:      "module.foo",
						ChildModules: []*tfjson.StateModule{},
					},
				},
			},
			resourceChanges: []*tfjson.ResourceChange{
				{
					Address: "null_resource.foo",
					Change: &tfjson.Change{
						BeforeSensitive: map[string]interface{}{
							"baz": true,
						},
						AfterSensitive: map[string]interface{}{
							"foo": true,
						},
					},
				},
				{
					Address: "module.foo.null_resource.bar",
					Change: &tfjson.Change{
						BeforeSensitive: map[string]interface{}{
							"a": true,
						},
						AfterSensitive: map[string]interface{}{
							"c": true,
						},
					},
				},
			},
			mode: SanitizeStateModuleChangeModeBefore,
			expected: &tfjson.StateModule{
				Resources: []*tfjson.StateResource{
					{
						Address: "null_resource.foo",
						AttributeValues: map[string]interface{}{
							"foo": "bar",
							"baz": DefaultSensitiveValue,
						},
					},
				},
				Address: "",
				ChildModules: []*tfjson.StateModule{
					&tfjson.StateModule{
						Resources: []*tfjson.StateResource{
							{
								Address: "module.foo.null_resource.bar",
								AttributeValues: map[string]interface{}{
									"a": DefaultSensitiveValue,
									"c": "d",
								},
							},
						},
						Address:      "module.foo",
						ChildModules: []*tfjson.StateModule{},
					},
				},
			},
		},
		{
			name: "after",
			old: &tfjson.StateModule{
				Resources: []*tfjson.StateResource{
					{
						Address: "null_resource.foo",
						AttributeValues: map[string]interface{}{
							"foo": "bar",
							"baz": "qux",
						},
					},
				},
				Address: "",
				ChildModules: []*tfjson.StateModule{
					&tfjson.StateModule{
						Resources: []*tfjson.StateResource{
							{
								Address: "module.foo.null_resource.bar",
								AttributeValues: map[string]interface{}{
									"a": "b",
									"c": "d",
								},
							},
						},
						Address:      "module.foo",
						ChildModules: []*tfjson.StateModule{},
					},
				},
			},
			resourceChanges: []*tfjson.ResourceChange{
				{
					Address: "null_resource.foo",
					Change: &tfjson.Change{
						BeforeSensitive: map[string]interface{}{
							"baz": true,
						},
						AfterSensitive: map[string]interface{}{
							"foo": true,
						},
					},
				},
				{
					Address: "module.foo.null_resource.bar",
					Change: &tfjson.Change{
						BeforeSensitive: map[string]interface{}{
							"a": true,
						},
						AfterSensitive: map[string]interface{}{
							"c": true,
						},
					},
				},
			},
			mode: SanitizeStateModuleChangeModeAfter,
			expected: &tfjson.StateModule{
				Resources: []*tfjson.StateResource{
					{
						Address: "null_resource.foo",
						AttributeValues: map[string]interface{}{
							"foo": DefaultSensitiveValue,
							"baz": "qux",
						},
					},
				},
				Address: "",
				ChildModules: []*tfjson.StateModule{
					&tfjson.StateModule{
						Resources: []*tfjson.StateResource{
							{
								Address: "module.foo.null_resource.bar",
								AttributeValues: map[string]interface{}{
									"a": "b",
									"c": DefaultSensitiveValue,
								},
							},
						},
						Address:      "module.foo",
						ChildModules: []*tfjson.StateModule{},
					},
				},
			},
		},
	}
}

func TestSanitizeStateModule(t *testing.T) {
	for _, tc := range stateCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.old
			SanitizeStateModule(actual, tc.resourceChanges, tc.mode, DefaultSensitiveValue)

			if diff := cmp.Diff(tc.expected, actual); diff != "" {
				t.Errorf("SanitizeStateModule() mismatch (-expected +actual):\n%s", diff)
			}
		})
	}
}

type testOutputCase struct {
	name     string
	old      map[string]*tfjson.StateOutput
	expected map[string]*tfjson.StateOutput
}

func outputCases() []testOutputCase {
	return []testOutputCase{
		{
			name: "nil values",
			old: map[string]*tfjson.StateOutput{
				"foo": nil,
			},
			expected: map[string]*tfjson.StateOutput{
				"foo": nil,
			},
		},
		{
			name: "basic",
			old: map[string]*tfjson.StateOutput{
				"foo": {
					Value: "bar",
				},
				"a": {
					Value:     "b",
					Sensitive: true,
				},
			},
			expected: map[string]*tfjson.StateOutput{
				"foo": {
					Value: "bar",
				},
				"a": {
					Value:     DefaultSensitiveValue,
					Sensitive: true,
				},
			},
		},
	}
}

func TestSanitizeStateOutputs(t *testing.T) {
	for _, tc := range outputCases() {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.old
			SanitizeStateOutputs(tc.old, DefaultSensitiveValue)

			if diff := cmp.Diff(tc.expected, actual, ctydebug.CmpOptions); diff != "" {
				t.Errorf("SanitizeStateOutputs() mismatch (-expected +actual):\n%s", diff)
			}
		})
	}
}
