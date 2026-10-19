package rules

import "testing"

func TestDefaultRulesParse(t *testing.T) {
	rs, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if len(rs) == 0 {
		t.Fatal("no built-in rules")
	}
}

func TestExpandUnsetVariable(t *testing.T) {
	t.Setenv("DEVSWEEP_UNSET_TEST", "")
	for _, p := range []string{`%DEVSWEEP_UNSET_TEST%\cache`, "$DEVSWEEP_UNSET_TEST/cache", "relative/dir"} {
		if got := Expand(p); got != "" {
			t.Errorf("Expand(%q) = %q, want empty (never resolve relative to a root)", p, got)
		}
	}
}
