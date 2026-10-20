package store

import (
	"database/sql"
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
