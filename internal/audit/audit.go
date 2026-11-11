// Package audit is the gateway's append-only record of every exchange.
//
// Records live in a SQLite table that refuses UPDATE and DELETE. Each row
// also carries a hash of itself and the row before it, so editing or
// removing a row behind SQLite's back breaks the chain and Verify reports
// it. The chain shows tampering; it does not prevent someone with write
// access to the file from replacing the whole log.
package audit

import (
	"bufio"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite" // pure-Go SQLite driver
)

// MaxArgumentBytes is the most argument data stored per record. Larger
// arguments are left out; their size and hash are still recorded.
const MaxArgumentBytes = 64 << 10

const genesisHash = "0000000000000000000000000000000000000000000000000000000000000000"

// Record is one exchange through the gateway.
type Record struct {
	Time       time.Time `json:"time"`
	Server     string    `json:"server"`
	Agent      string    `json:"agent,omitempty"`
	HTTPMethod string    `json:"http_method"`
	Kind       string    `json:"kind,omitempty"`
	RPCMethod  string    `json:"rpc_method,omitempty"`
	RPCID      string    `json:"rpc_id,omitempty"`
	Tool       string    `json:"tool,omitempty"`

	Arguments       json.RawMessage `json:"arguments,omitempty"`
	ArgumentsBytes  int             `json:"arguments_bytes,omitempty"`
	ArgumentsSHA256 string          `json:"arguments_sha256,omitempty"`

	Allowed       bool   `json:"allowed"`
	Code          string `json:"code"`
	Reason        string `json:"reason,omitempty"`
	PolicyVersion string `json:"policy_version,omitempty"`

	ApprovalID     string `json:"approval_id,omitempty"`
	ApprovedBy     string `json:"approval_by,omitempty"`
	ApprovalWaitUS int64  `json:"approval_wait_us,omitempty"`

	Status     int   `json:"status"`
	DurationUS int64 `json:"duration_us"`           // whole exchange, microseconds
	UpstreamUS int64 `json:"upstream_us,omitempty"` // time spent in the MCP server
}

// Entry is a Record as stored, with its place in the chain.
type Entry struct {
	Seq      int64           `json:"seq"`
	PrevHash string          `json:"prev_hash"`
	Hash     string          `json:"hash"`
	Record   json.RawMessage `json:"record"`
}

// Log is an open audit log. It is safe for concurrent use.
type Log struct {
	db *sql.DB

	mu   sync.Mutex
	last string // hash of the newest row
}

const schemaSQL = `
CREATE TABLE IF NOT EXISTS audit_log (
	seq       INTEGER PRIMARY KEY AUTOINCREMENT,
	prev_hash TEXT NOT NULL,
	hash      TEXT NOT NULL,
	record    TEXT NOT NULL
);
CREATE TRIGGER IF NOT EXISTS audit_log_no_update BEFORE UPDATE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_log_no_delete BEFORE DELETE ON audit_log
BEGIN SELECT RAISE(ABORT, 'audit_log is append-only'); END;
`

// Open opens or creates the log at path.
func Open(path string) (*Log, error) {
	if path == "" {
		return nil, errors.New("audit: empty path")
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	// One connection: the pragmas below are per connection, and a single
	// writer keeps the hash chain simple.
	db.SetMaxOpenConns(1)

	for _, stmt := range []string{
		"PRAGMA journal_mode = WAL",
		"PRAGMA synchronous = NORMAL",
		"PRAGMA busy_timeout = 5000",
		schemaSQL,
	} {
		if _, err := db.Exec(stmt); err != nil {
			db.Close()
			return nil, fmt.Errorf("audit: preparing %s: %w", path, err)
		}
	}

	l := &Log{db: db, last: genesisHash}
	err = db.QueryRow("SELECT hash FROM audit_log ORDER BY seq DESC LIMIT 1").Scan(&l.last)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		db.Close()
		return nil, fmt.Errorf("audit: reading %s: %w", path, err)
	}
	return l, nil
}

// Close closes the log.
func (l *Log) Close() error { return l.db.Close() }

// Append writes one record. An error means the record was not stored.
func (l *Log) Append(r Record) error {
	if n := len(r.Arguments); n > 0 {
		sum := sha256.Sum256(r.Arguments)
		r.ArgumentsBytes = n
		r.ArgumentsSHA256 = hex.EncodeToString(sum[:])
		if n > MaxArgumentBytes || !json.Valid(r.Arguments) {
			r.Arguments = nil
		}
	}
	r.Time = r.Time.UTC()
	body, err := json.Marshal(r)
	if err != nil {
		return fmt.Errorf("audit: %w", err)
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	hash := chainHash(l.last, body)
	if _, err := l.db.Exec("INSERT INTO audit_log (prev_hash, hash, record) VALUES (?, ?, ?)",
		l.last, hash, string(body)); err != nil {
		return fmt.Errorf("audit: append: %w", err)
	}
	l.last = hash
	return nil
}

func chainHash(prev string, record []byte) string {
	h := sha256.New()
	h.Write([]byte(prev))
	h.Write([]byte{'\n'})
	h.Write(record)
	return hex.EncodeToString(h.Sum(nil))
}

// each calls fn for every entry in order, checking the chain as it goes.
func (l *Log) each(fn func(Entry) error) (int, error) {
	rows, err := l.db.Query("SELECT seq, prev_hash, hash, record FROM audit_log ORDER BY seq")
	if err != nil {
		return 0, fmt.Errorf("audit: %w", err)
	}
	defer rows.Close()

	n, prev := 0, genesisHash
	for rows.Next() {
		var e Entry
		var record string
		if err := rows.Scan(&e.Seq, &e.PrevHash, &e.Hash, &record); err != nil {
			return n, fmt.Errorf("audit: %w", err)
		}
		e.Record = json.RawMessage(record)
		if e.PrevHash != prev {
			return n, fmt.Errorf("audit: chain broken at seq %d: a record before it was removed or altered", e.Seq)
		}
		if chainHash(e.PrevHash, e.Record) != e.Hash {
			return n, fmt.Errorf("audit: record at seq %d was altered", e.Seq)
		}
		if !json.Valid(e.Record) {
			return n, fmt.Errorf("audit: record at seq %d is not valid JSON", e.Seq)
		}
		prev = e.Hash
		n++
		if fn != nil {
			if err := fn(e); err != nil {
				return n, err
			}
		}
	}
	return n, rows.Err()
}

// Verify checks the whole chain and returns the number of records.
func (l *Log) Verify() (int, error) { return l.each(nil) }

// Export writes every entry as one JSON object per line (JSON Lines) and
// returns how many it wrote. It verifies the chain as it goes and stops at
// the first broken entry.
func (l *Log) Export(w io.Writer) (int, error) {
	bw := bufio.NewWriter(w)
	enc := json.NewEncoder(bw)
	n, err := l.each(func(e Entry) error { return enc.Encode(e) })
	if flushErr := bw.Flush(); err == nil {
		err = flushErr
	}
	return n, err
}

// RawID renders a JSON-RPC id for a record: 7 -> "7", "a" -> "a".
func RawID(id json.RawMessage) string {
	s := strings.TrimSpace(string(id))
	if strings.HasPrefix(s, `"`) {
		var str string
		if json.Unmarshal(id, &str) == nil {
			return str
		}
	}
	return s
}
