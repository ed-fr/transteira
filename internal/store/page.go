package store

import (
	"database/sql"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/id"
)

// Page sizes for list operations.
const (
	// DefaultPageSize is used when a list request does not set a limit.
	DefaultPageSize = 50
	// MaxPageSize caps the limit of a list request (spec: maximum 200).
	MaxPageSize = 200
)

// Page is one page of a cursor-paginated list.
type Page[T any] struct {
	// Items are the elements of the page, in a stable order.
	Items []T
	// NextCursor is the opaque cursor of the next page, or "" on the last
	// page.
	NextCursor string
}

// pageLimit returns the effective page size for a requested limit: the
// default when limit <= 0, capped at MaxPageSize.
func pageLimit(limit int) int {
	switch {
	case limit <= 0:
		return DefaultPageSize
	case limit > MaxPageSize:
		return MaxPageSize
	}
	return limit
}

// paginate turns the limit+1 rows fetched by a list query into a page:
// the extra row, if present, proves that a next page exists and is dropped.
func paginate[T any](items []T, limit int, cursor func(T) string) Page[T] {
	if len(items) <= limit {
		return Page[T]{Items: items}
	}
	items = items[:limit]
	return Page[T]{Items: items, NextCursor: cursor(items[limit-1])}
}

// collect scans every row with scan and closes rows. It returns an empty,
// non-nil slice when there is no row.
func collect[T any](rows *sql.Rows, scan func(*sql.Rows) (T, error)) ([]T, error) {
	defer func() { _ = rows.Close() }()
	out := make([]T, 0)
	for rows.Next() {
		v, err := scan(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// timeCursor returns the keyset cursor "<unix ms>:<id>" of a list ordered
// by (time, id), newest first.
func timeCursor(at time.Time, rowID string) string {
	return strconv.FormatInt(toMillis(at), 10) + ":" + rowID
}

// parseTimeCursor reads a cursor of timeCursor whose identifier has prefix
// p. "" starts from the newest row: it returns the largest time and "".
func parseTimeCursor(c string, p id.Prefix) (int64, string, error) {
	if c == "" {
		return math.MaxInt64, "", nil
	}
	ms, rowID, ok := strings.Cut(c, ":")
	at, err := strconv.ParseInt(ms, 10, 64)
	if !ok || err != nil || !id.Valid(p, rowID) || strconv.FormatInt(at, 10) != ms {
		return 0, "", invalid("malformed cursor")
	}
	return at, rowID, nil
}
