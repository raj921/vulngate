package report

import (
	"encoding/json"
	"testing"
)

func TestSARIFEmptyRulesIsArray(t *testing.T) {
	data, err := SARIF(nil)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		t.Fatal(err)
	}
	runs := parsed["runs"].([]any)
	tool := runs[0].(map[string]any)["tool"].(map[string]any)
	driver := tool["driver"].(map[string]any)
	rules, ok := driver["rules"].([]any)
	if !ok {
		t.Fatalf("rules want array, got %T (%v)", driver["rules"], driver["rules"])
	}
	if len(rules) != 0 {
		t.Fatalf("rules want empty, got %#v", rules)
	}
}
