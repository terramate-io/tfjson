// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package sanitize

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sebdah/goldie/v2"

	"github.com/terramate-io/tfjson"
)

const testDataDir = "testdata"

func TestSanitizePlanEmpty(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		err := SanitizePlan(nil)
		if !errors.Is(err, NilPlanError) {
			t.Error("expected NilPlanError")
		}
	})

	t.Run("empty", func(t *testing.T) {
		plan := tfjson.Plan{}
		err := SanitizePlan(&plan)
		if err != nil {
			t.Error(err)
		}
	})
}

func TestSanitizePlanGolden(t *testing.T) {
	cases, err := goldenCases()
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range cases {
		t.Run(tc.Name(), testSanitizePlanGoldenEntry(tc))
	}
}

func testSanitizePlanGoldenEntry(c testGoldenCase) func(t *testing.T) {
	return func(t *testing.T) {
		p := new(tfjson.Plan)
		err := json.Unmarshal(c.InputData, p)
		if err != nil {
			t.Fatal(err)
		}

		err = SanitizePlan(p)
		if err != nil {
			t.Fatal(err)
		}

		g := goldie.New(t)
		if err = g.WithFixtureDir(testDataDir); err != nil {
			t.Fatal(err)
		}
		g.AssertJson(t, c.Name(), p)
	}
}

type testGoldenCase struct {
	FileName  string
	InputData []byte
}

func (c *testGoldenCase) Name() string {
	return strings.TrimSuffix(c.FileName, filepath.Ext(c.FileName))
}

func goldenCases() ([]testGoldenCase, error) {
	d, err := os.Open(testDataDir)
	if err != nil {
		return nil, err
	}

	entries, err := d.ReadDir(0)
	if err != nil {
		return nil, err
	}

	result := make([]testGoldenCase, 0)
	for _, e := range entries {
		if !e.Type().IsRegular() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}

		data, err := os.ReadFile(filepath.Join(testDataDir, e.Name()))
		if err != nil {
			return nil, err
		}

		result = append(result, testGoldenCase{
			FileName:  e.Name(),
			InputData: data,
		})
	}

	return result, err
}

func BenchmarkLargeChangeset(b *testing.B) {
	b.StopTimer()
	data, err := os.ReadFile(filepath.Join(testDataDir, "basic.json"))
	if err != nil {
		b.Fatal(err)
	}
	p := new(tfjson.Plan)
	err = json.Unmarshal(data, p)
	if err != nil {
		b.Fatal(err)
	}
	b.StartTimer()

	for i := 0; i < b.N; i++ {
		err = SanitizePlan(p)
		if err != nil {
			b.Fatal(err)
		}
		if p == nil {
			b.Fatal(err)
		}
	}
}
