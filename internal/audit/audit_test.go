package audit

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func record(i int) Record {
	return Record{
		Time:          time.Date(2026, 11, 11, 12, 0, i, 0, time.UTC),
		Server:        "files",
		Agent:         "alpha",
		HTTPMethod:    "POST",
		Kind:          "request",
		RPCMethod:     "tools/call",
		RPCID:         "7",
		Tool:          "read_file",
		Arguments:     json.RawMessage(`{"path":"/workspace/a.txt"}`),
		Allowed:       i%2 == 0,
		Code:          "allowed",
		PolicyVersion: "abc123",
		Status:        200,
		DurationUS:    1500,
		UpstreamUS:    1200,
	}
}

func openTemp(t *testing.T) (*Log, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l, path
}

func export(t *testing.T, l *Log) []Entry {
	t.Helper()
	var buf bytes.Buffer
	n, err := l.Export(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var entries []Entry
	for _, line := range strings.Split(strings.TrimSpace(buf.String()), "\n") {
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			t.Fatalf("export line is not JSON: %v\n%s", err, line)
		}
		entries = append(entries, e)
	}
	if n != len(entries) {
		t.Fatalf("Export reported %d entries, wrote %d", n, len(entries))
	}
	return entries
}

func TestAppendExportVerify(t *testing.T) {
	l, _ := openTemp(t)
	if n, err := l.Verify(); n != 0 || err != nil {
		t.Fatalf("empty log: n=%d err=%v", n, err)
	}
	for i := 0; i < 5; i++ {
		if err := l.Append(record(i)); err != nil {
			t.Fatal(err)
		}
	}
	if n, err := l.Verify(); n != 5 || err != nil {
		t.Fatalf("Verify: n=%d err=%v", n, err)
	}

	entries := export(t, l)
	if len(entries) != 5 {
		t.Fatalf("exported %d entries, want 5", len(entries))
	}
	prev := genesisHash
	for i, e := range entries {
		if e.Seq != int64(i+1) || e.PrevHash != prev || len(e.Hash) != 64 {
			t.Errorf("entry %d not chained: %+v", i, e)
		}
		prev = e.Hash
		var r Record
		if err := json.Unmarshal(e.Record, &r); err != nil {
			t.Fatal(err)
		}
		if r.Tool != "read_file" || r.Agent != "alpha" || r.PolicyVersion != "abc123" ||
			r.DurationUS != 1500 || r.Allowed != (i%2 == 0) || !r.Time.Equal(record(i).Time) {
			t.Errorf("entry %d round-tripped wrongly: %+v", i, r)
		}
		if string(r.Arguments) != `{"path":"/workspace/a.txt"}` || len(r.ArgumentsSHA256) != 64 || r.ArgumentsBytes != 27 {
			t.Errorf("entry %d arguments: %s (%d bytes, sha %s)", i, r.Arguments, r.ArgumentsBytes, r.ArgumentsSHA256)
		}
	}
}

func TestReopenContinuesChain(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	for round := 0; round < 3; round++ {
		l, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := l.Append(record(round)); err != nil {
			t.Fatal(err)
		}
		if n, err := l.Verify(); n != round+1 || err != nil {
			t.Fatalf("round %d: n=%d err=%v", round, n, err)
		}
		l.Close()
	}
}

func TestConcurrentAppends(t *testing.T) {
	l, _ := openTemp(t)
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := l.Append(record(i)); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if n, err := l.Verify(); n != 50 || err != nil {
		t.Fatalf("Verify: n=%d err=%v", n, err)
	}
}

func TestLargeOrInvalidArgumentsAreHashedNotStored(t *testing.T) {
	l, _ := openTemp(t)
	big := record(0)
	big.Arguments = json.RawMessage(`{"text":"` + strings.Repeat("a", MaxArgumentBytes) + `"}`)
	bad := record(1)
	bad.Arguments = json.RawMessage(`{"text":`)
	for _, r := range []Record{big, bad} {
		if err := l.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	for i, e := range export(t, l) {
		var r Record
		if err := json.Unmarshal(e.Record, &r); err != nil {
			t.Fatal(err)
		}
		if r.Arguments != nil || len(r.ArgumentsSHA256) != 64 || r.ArgumentsBytes == 0 {
			t.Errorf("entry %d: arguments=%d bytes stored, sha=%q, size=%d", i, len(r.Arguments), r.ArgumentsSHA256, r.ArgumentsBytes)
		}
	}
}

// TestAppendOnly: SQL cannot change history, and changes made by going
// around the triggers are detected.
func TestAppendOnly(t *testing.T) {
	l, _ := openTemp(t)
	for i := 0; i < 4; i++ {
		if err := l.Append(record(i)); err != nil {
			t.Fatal(err)
		}
	}

	for _, stmt := range []string{
		`UPDATE audit_log SET record = '{}' WHERE seq = 2`,
		`DELETE FROM audit_log WHERE seq = 2`,
		`DELETE FROM audit_log`,
	} {
		if _, err := l.db.Exec(stmt); err == nil || !strings.Contains(err.Error(), "append-only") {
			t.Errorf("%s: err = %v, want an append-only refusal", stmt, err)
		}
	}
	if n, err := l.Verify(); n != 4 || err != nil {
		t.Fatalf("log changed by refused statements: n=%d err=%v", n, err)
	}
}

// TestTamperingIsDetected: someone with the file removes the triggers and
// changes history. SQLite cannot stop that; the hash chain shows it.
func TestTamperingIsDetected(t *testing.T) {
	tests := map[string][]string{
		"edited record": {`DROP TRIGGER audit_log_no_update`,
			`UPDATE audit_log SET record = replace(record, '"allowed":false', '"allowed":true') WHERE seq = 2`},
		"deleted record":       {`DROP TRIGGER audit_log_no_delete`, `DELETE FROM audit_log WHERE seq = 3`},
		"deleted first record": {`DROP TRIGGER audit_log_no_delete`, `DELETE FROM audit_log WHERE seq = 1`},
		"rewritten hash": {`DROP TRIGGER audit_log_no_update`,
			`UPDATE audit_log SET record = '{}', hash = 'ffff' WHERE seq = 4`},
	}
	for name, stmts := range tests {
		t.Run(name, func(t *testing.T) {
			l, path := openTemp(t)
			for i := 0; i < 4; i++ {
				if err := l.Append(record(i)); err != nil {
					t.Fatal(err)
				}
			}
			l.Close()

			db, err := sql.Open("sqlite", path)
			if err != nil {
				t.Fatal(err)
			}
			for _, s := range stmts {
				if _, err := db.Exec(s); err != nil {
					t.Fatalf("%s: %v", s, err)
				}
			}
			db.Close()

			reopened, err := Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			if _, err := reopened.Verify(); err == nil {
				t.Error("Verify did not detect the change")
			}
			if _, err := reopened.Export(&bytes.Buffer{}); err == nil {
				t.Error("Export did not detect the change")
			}
		})
	}
}

func TestRawID(t *testing.T) {
	for in, want := range map[string]string{`7`: "7", `"abc"`: "abc", `null`: "null", ``: ""} {
		if got := RawID(json.RawMessage(in)); got != want {
			t.Errorf("RawID(%s) = %q, want %q", in, got, want)
		}
	}
}
