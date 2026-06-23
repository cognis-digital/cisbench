package cisbench

import (
	"encoding/json"
	"strings"
	"testing"
)

func inv(t *testing.T, s string) interface{} {
	t.Helper()
	dec := json.NewDecoder(strings.NewReader(s))
	dec.UseNumber()
	var v interface{}
	if err := dec.Decode(&v); err != nil {
		t.Fatalf("bad json: %v", err)
	}
	return v
}

func TestBuiltinProfileHas12Checks(t *testing.T) {
	if n := len(BuiltinProfile().Checks); n != 12 {
		t.Fatalf("expected 12 checks, got %d", n)
	}
}

func TestEvaluateIsTrue(t *testing.T) {
	c := Check{ID: "x", Path: "network.require_tls", Operator: "is_true", Severity: "critical"}
	if !EvaluateCheck(c, inv(t, `{"network":{"require_tls":true}}`)).Passed {
		t.Fatal("expected pass")
	}
	if EvaluateCheck(c, inv(t, `{"network":{"require_tls":false}}`)).Passed {
		t.Fatal("expected fail")
	}
}

func TestEvaluateGte(t *testing.T) {
	c := Check{ID: "x", Path: "auth.password_min_length", Operator: "gte", Expected: 14.0, Severity: "high"}
	if !EvaluateCheck(c, inv(t, `{"auth":{"password_min_length":16}}`)).Passed {
		t.Fatal("16 >= 14 should pass")
	}
	if EvaluateCheck(c, inv(t, `{"auth":{"password_min_length":8}}`)).Passed {
		t.Fatal("8 >= 14 should fail")
	}
}

func TestMissingValueFails(t *testing.T) {
	c := Check{ID: "x", Path: "auth.len", Operator: "gte", Expected: 14.0, Severity: "high"}
	if EvaluateCheck(c, inv(t, `{"auth":{}}`)).Passed {
		t.Fatal("missing should fail")
	}
}

func TestNotEqualsBindAddress(t *testing.T) {
	c := Check{ID: "x", Path: "network.bind_address", Operator: "not_equals", Expected: "0.0.0.0", Severity: "high"}
	if !EvaluateCheck(c, inv(t, `{"network":{"bind_address":"10.0.0.1"}}`)).Passed {
		t.Fatal("non-0.0.0.0 should pass")
	}
	if EvaluateCheck(c, inv(t, `{"network":{"bind_address":"0.0.0.0"}}`)).Passed {
		t.Fatal("0.0.0.0 should fail")
	}
}

func TestResolveNestedAndIndex(t *testing.T) {
	v := inv(t, `{"a":{"b":{"c":5}},"u":[{"n":"x"},{"n":"y"}]}`)
	if got := resolvePath(v, "u.1.n"); got != "y" {
		t.Fatalf("expected y, got %v", got)
	}
	if resolvePath(v, "a.z") != missing {
		t.Fatal("expected missing for a.z")
	}
}

func TestScanScores(t *testing.T) {
	hardened := `{
		"network":{"require_tls":true,"min_tls_version":1.3,"bind_address":"10.0.0.5"},
		"auth":{"password_min_length":16,"password_complexity_enabled":true,
		        "failed_login_lockout_threshold":5,"anonymous_login_enabled":false},
		"audit":{"logging_enabled":true,"retention_days":365},
		"accounts":{"default_admin_renamed":true},
		"storage":{"encryption_at_rest":true},
		"diagnostics":{"verbose_client_errors":false}}`
	r := Scan(BuiltinProfile(), inv(t, hardened))
	if r.Score() != 100.0 {
		t.Fatalf("hardened should score 100, got %v", r.Score())
	}
	if r.Failed() != 0 {
		t.Fatalf("hardened should have 0 failures, got %d", r.Failed())
	}
}

func TestScanWeightedScore(t *testing.T) {
	r := Scan(BuiltinProfile(), inv(t, `{"network":{"require_tls":true}}`))
	if r.WeightedScore() <= 0 || r.WeightedScore() >= 100 {
		t.Fatalf("weighted score should be partial, got %v", r.WeightedScore())
	}
	if r.Passed() != 1 {
		t.Fatalf("expected 1 pass, got %d", r.Passed())
	}
}

func TestToMapShape(t *testing.T) {
	r := Scan(BuiltinProfile(), inv(t, `{"network":{"require_tls":true}}`))
	m := r.ToMap()
	if m["profile"] != "cognis-db-baseline" {
		t.Fatalf("bad profile name: %v", m["profile"])
	}
	summary := m["summary"].(map[string]interface{})
	if summary["total"].(int) != 12 {
		t.Fatalf("expected total 12, got %v", summary["total"])
	}
}
