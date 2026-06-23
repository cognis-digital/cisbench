// Package cisbench is a Go port of the core passive evaluation engine of the
// Python cisbench tool: declarative hardening checks evaluated against an
// offline inventory snapshot, with a plain and a severity-weighted score.
//
// The control identifiers (CDB-*) and wording mirror the authored Python
// baseline; they are not copied from any external benchmark document.
package cisbench

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// severityWeight maps a severity to its weighted-score weight.
var severityWeight = map[string]int{
	"low": 1, "medium": 2, "high": 3, "critical": 4,
}

// Check is one declarative hardening expectation.
type Check struct {
	ID          string      `json:"id"`
	Title       string      `json:"title"`
	Path        string      `json:"path"`
	Operator    string      `json:"operator"`
	Expected    interface{} `json:"expected,omitempty"`
	Reference   string      `json:"reference"`
	Severity    string      `json:"severity"`
	Remediation string      `json:"remediation,omitempty"`
}

// Weight returns the severity-derived weight (default medium=2).
func (c Check) Weight() int {
	if w, ok := severityWeight[c.Severity]; ok {
		return w
	}
	return 2
}

// Profile is an ordered, named collection of checks.
type Profile struct {
	Name        string  `json:"name"`
	Version     string  `json:"version"`
	Description string  `json:"description"`
	Checks      []Check `json:"checks"`
}

// Result is the outcome of evaluating a single check.
type Result struct {
	Check    Check
	Passed   bool
	Evidence string
}

// Report aggregates the results of scanning a profile against an inventory.
type Report struct {
	Profile Profile
	Results []Result
}

func (r Report) Total() int { return len(r.Results) }

func (r Report) Passed() int {
	n := 0
	for _, res := range r.Results {
		if res.Passed {
			n++
		}
	}
	return n
}

func (r Report) Failed() int { return r.Total() - r.Passed() }

func (r Report) Score() float64 {
	if r.Total() == 0 {
		return 0
	}
	return round1(100 * float64(r.Passed()) / float64(r.Total()))
}

func (r Report) WeightedScore() float64 {
	total, earned := 0, 0
	for _, res := range r.Results {
		total += res.Check.Weight()
		if res.Passed {
			earned += res.Check.Weight()
		}
	}
	if total == 0 {
		return 0
	}
	return round1(100 * float64(earned) / float64(total))
}

// ToMap renders the report as the same JSON shape the Python tool emits.
func (r Report) ToMap() map[string]interface{} {
	results := make([]map[string]interface{}, 0, len(r.Results))
	for _, res := range r.Results {
		status := "PASS"
		if !res.Passed {
			status = "FAIL"
		}
		results = append(results, map[string]interface{}{
			"id":       res.Check.ID,
			"title":    res.Check.Title,
			"severity": res.Check.Severity,
			"status":   status,
			"evidence": res.Evidence,
		})
	}
	return map[string]interface{}{
		"profile":         r.Profile.Name,
		"profile_version": r.Profile.Version,
		"summary": map[string]interface{}{
			"total":          r.Total(),
			"passed":         r.Passed(),
			"failed":         r.Failed(),
			"score":          r.Score(),
			"weighted_score": r.WeightedScore(),
		},
		"results": results,
	}
}

func round1(f float64) float64 {
	s := strconv.FormatFloat(f, 'f', 1, 64)
	v, _ := strconv.ParseFloat(s, 64)
	return v
}

// missing is a sentinel distinguishing "absent" from "present but nil".
type missingT struct{}

var missing = missingT{}

// resolvePath resolves a dotted path against the inventory.
func resolvePath(inv interface{}, path string) interface{} {
	cur := inv
	for _, seg := range strings.Split(path, ".") {
		switch c := cur.(type) {
		case map[string]interface{}:
			v, ok := c[seg]
			if !ok {
				return missing
			}
			cur = v
		case []interface{}:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(c) {
				return missing
			}
			cur = c[idx]
		default:
			return missing
		}
	}
	return cur
}

func asNumber(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case int:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func truthy(v interface{}) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return t != ""
	case float64:
		return t != 0
	case nil:
		return false
	}
	return true
}

// EvaluateCheck evaluates one check against an inventory.
func EvaluateCheck(c Check, inv interface{}) Result {
	observed := resolvePath(inv, c.Path)
	present := observed != missing

	switch c.Operator {
	case "present":
		return Result{c, present, presenceEvidence(c.Path, present, true)}
	case "absent":
		return Result{c, !present, presenceEvidence(c.Path, present, false)}
	}

	if !present {
		return Result{c, false,
			fmt.Sprintf("setting '%s' is missing; cannot satisfy '%s' (FAIL)",
				c.Path, c.Operator)}
	}

	passed, ok := applyOperator(c.Operator, observed, c.Expected)
	if !ok {
		return Result{c, false,
			fmt.Sprintf("could not evaluate '%s' on '%s' (observed %v)",
				c.Operator, c.Path, observed)}
	}
	rel := "matches"
	if !passed {
		rel = "does not match"
	}
	ev := fmt.Sprintf("'%s' = %v %s expectation (%s %v)",
		c.Path, observed, rel, c.Operator, c.Expected)
	if c.Operator == "is_true" || c.Operator == "is_false" {
		verb := "satisfies"
		if !passed {
			verb = "violates"
		}
		ev = fmt.Sprintf("'%s' = %v (%s %s)", c.Path, observed, verb,
			strings.ReplaceAll(c.Operator, "_", " "))
	}
	return Result{c, passed, ev}
}

func presenceEvidence(path string, present, wantPresent bool) string {
	if wantPresent {
		if present {
			return fmt.Sprintf("setting '%s' is present", path)
		}
		return fmt.Sprintf("setting '%s' is missing", path)
	}
	if present {
		return fmt.Sprintf("setting '%s' is present but should be absent", path)
	}
	return fmt.Sprintf("setting '%s' is absent (as required)", path)
}

func applyOperator(op string, v, e interface{}) (bool, bool) {
	switch op {
	case "equals":
		return equalish(v, e), true
	case "not_equals":
		return !equalish(v, e), true
	case "gte", "lte", "gt", "lt":
		vn, ok1 := asNumber(v)
		en, ok2 := asNumber(e)
		if !ok1 || !ok2 {
			return false, false
		}
		switch op {
		case "gte":
			return vn >= en, true
		case "lte":
			return vn <= en, true
		case "gt":
			return vn > en, true
		default:
			return vn < en, true
		}
	case "is_true":
		return truthy(v), true
	case "is_false":
		return !truthy(v), true
	case "in":
		if list, ok := e.([]interface{}); ok {
			for _, x := range list {
				if equalish(v, x) {
					return true, true
				}
			}
			return false, true
		}
		return false, false
	case "not_in":
		ok, valid := applyOperator("in", v, e)
		return !ok, valid
	case "contains":
		if list, ok := v.([]interface{}); ok {
			for _, x := range list {
				if equalish(x, e) {
					return true, true
				}
			}
			return false, true
		}
		if s, ok := v.(string); ok {
			if es, ok := e.(string); ok {
				return strings.Contains(s, es), true
			}
		}
		return false, false
	case "not_contains":
		ok, valid := applyOperator("contains", v, e)
		return !ok, valid
	}
	return false, false
}

func equalish(a, b interface{}) bool {
	if an, ok := asNumber(a); ok {
		if bn, ok := asNumber(b); ok {
			return an == bn
		}
	}
	return fmt.Sprintf("%v", a) == fmt.Sprintf("%v", b)
}

// Scan evaluates every check in the profile against the inventory.
func Scan(p Profile, inv interface{}) Report {
	results := make([]Result, 0, len(p.Checks))
	for _, c := range p.Checks {
		results = append(results, EvaluateCheck(c, inv))
	}
	return Report{Profile: p, Results: results}
}

// LoadInventory reads an inventory snapshot, unwrapping an optional top-level
// "settings" object so snapshots can carry metadata.
func LoadInventory(path string) (interface{}, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("inventory file not found: %s", path)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.UseNumber()
	var data interface{}
	if err := dec.Decode(&data); err != nil {
		return nil, fmt.Errorf("inventory is not valid JSON: %v", err)
	}
	if m, ok := data.(map[string]interface{}); ok {
		if s, ok := m["settings"].(map[string]interface{}); ok {
			return s, nil
		}
	}
	return data, nil
}
