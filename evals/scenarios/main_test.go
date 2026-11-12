package main

import "testing"

// TestScenarioSuite keeps the suite honest: it must stay large enough, keep
// a held-out split, and the dev scenarios must not regress. Held-out misses
// are reported, never asserted on: fixing one by editing rules would defeat
// the point of holding it out.
func TestScenarioSuite(t *testing.T) {
	rep, err := runAll()
	if err != nil {
		t.Fatal(err)
	}
	if rep.Scenarios < 50 {
		t.Errorf("only %d scenarios; the suite needs at least 50", rep.Scenarios)
	}
	for _, split := range []string{"dev", "heldout"} {
		for _, group := range []string{"attacks blocked", "benign working"} {
			if rep.Summary["both"][split][group].Total == 0 {
				t.Errorf("no %q scenarios in the %s split", group, split)
			}
		}
	}

	// With the gateway off, every attack must succeed and every benign task
	// must work. Otherwise the scenario, not the gateway, is doing the blocking.
	off := rep.Summary["off"]["all"]
	if off["attacks blocked"].Pass != 0 {
		t.Errorf("%d attacks fail even with the gateway off; those scenarios prove nothing", off["attacks blocked"].Pass)
	}
	if b := off["benign working"]; b.Pass != b.Total {
		t.Errorf("%d benign scenarios fail with the gateway off", b.Total-b.Pass)
	}
	// Policy alone must never break a benign task: the policy was written for them.
	if b := rep.Summary["policy"]["all"]["benign working"]; b.Pass != b.Total {
		t.Errorf("the policy refuses %d benign scenarios", b.Total-b.Pass)
	}

	for _, sc := range rep.Index {
		out := rep.Results[sc.ID]["both"]
		switch {
		case sc.Split == "dev" && !out.Pass:
			t.Errorf("dev scenario %s regressed (%s): %s", sc.ID, sc.Description, out.Detail)
		case !out.Pass:
			t.Logf("held-out miss %s (%s): %s", sc.ID, sc.Description, out.Detail)
		}
	}
	both := rep.Summary["both"]["heldout"]
	t.Logf("HELD-OUT, both layers: %d/%d attacks blocked, %d/%d benign working",
		both["attacks blocked"].Pass, both["attacks blocked"].Total, both["benign working"].Pass, both["benign working"].Total)
}
