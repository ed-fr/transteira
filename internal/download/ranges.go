package download

import (
	"cmp"
	"encoding/binary"
	"errors"
	"maps"
	"math"
	"slices"

	"github.com/ed-fr/transteira/internal/id"
	"github.com/ed-fr/transteira/internal/storage"
	"github.com/ed-fr/transteira/internal/store"
)

// Served range bookkeeping (decision P23). The state of a transfer maps the
// ID of each file requested so far to the union of the byte ranges served,
// as sorted, disjoint and non-adjacent spans. It is kept on disk in the
// state file storage.StateName(transferID), never in the database.
//
// Encoding (version 1), all integers unsigned varints:
//
//	version byte (1)
//	number of files
//	per file, by ascending ID: ID length, ID bytes, number of spans,
//	  per span: gap from the end of the previous span (from 0 for the
//	  first), length (at least 1)
//
// A file present with no span is an empty file that was requested.

// stateVersion is the version byte of the state encoding.
const stateVersion = 1

// maxContentSpans bounds the spans one response records; further disjoint
// reads are not credited (never more than what was served is recorded).
const maxContentSpans = 64

// errCorruptState reports a state file that does not decode.
var errCorruptState = errors.New("download: corrupt range state")

// errStateTooLarge reports a state that cannot fit storage.MaxStateSize even
// without any span.
var errStateTooLarge = errors.New("download: range state too large")

// span is the half-open byte range [start, end) of a file, start < end.
type span struct {
	start, end int64
}

// addSpan merges sp into the sorted, disjoint and non-adjacent spans list
// and returns the result, which keeps those properties.
func addSpan(list []span, sp span) []span {
	out := make([]span, 0, len(list)+1)
	i := 0
	for ; i < len(list) && list[i].end < sp.start; i++ {
		out = append(out, list[i])
	}
	for ; i < len(list) && list[i].start <= sp.end; i++ {
		sp.start, sp.end = min(sp.start, list[i].start), max(sp.end, list[i].end)
	}
	out = append(out, sp)
	return append(out, list[i:]...)
}

// served is the range state of a transfer.
type served map[string][]span

// covered returns the number of bytes the spans of list cover.
func covered(list []span) int64 {
	var n int64
	for _, sp := range list {
		n += sp.end - sp.start
	}
	return n
}

// add records that the spans of the file fileID of size bytes were served,
// clamped to the file; an empty file is recorded as requested. It returns
// the bytes newly covered and whether the state changed.
func (st served) add(fileID string, size int64, spans []span) (gained int64, changed bool) {
	list, known := st[fileID]
	if size == 0 {
		st[fileID] = list
		return 0, !known
	}
	before := covered(list)
	for _, sp := range spans {
		sp.start, sp.end = max(sp.start, 0), min(sp.end, size)
		if sp.start < sp.end {
			list = addSpan(list, sp)
		}
	}
	if len(list) == 0 {
		return 0, false
	}
	st[fileID] = list
	gained = covered(list) - before
	return gained, gained > 0
}

// fileDone reports whether every byte of f was served (an empty file once
// requested).
func (st served) fileDone(f store.TransferFile) bool {
	list, ok := st[f.ID]
	return ok && (f.Size == 0 || (len(list) == 1 && list[0].start == 0 && list[0].end >= f.Size))
}

// spanCount returns the number of spans of st.
func (st served) spanCount() int {
	n := 0
	for _, list := range st {
		n += len(list)
	}
	return n
}

// complete reports whether every byte of every file of files was served at
// least once (an empty file once requested).
func (st served) complete(files []store.TransferFile) bool {
	for _, f := range files {
		if !st.fileDone(f) {
			return false
		}
	}
	return true
}

// encode returns the encoding of st, within storage.MaxStateSize: when it
// would not fit, the shortest spans are dropped (never crediting more than
// was served) until it does. Each round drops as many spans as the excess
// would hold at the average size of a span in the encoding (at least one);
// the next round drops more when that was not enough. It returns
// errStateTooLarge when even the files without spans do not fit.
func (st served) encode() ([]byte, error) {
	for {
		b := st.marshal()
		excess := len(b) - storage.MaxStateSize
		if excess <= 0 {
			return b, nil
		}
		n := st.spanCount()
		if n == 0 {
			return nil, errStateTooLarge
		}
		st.drop(max(excess*n/len(b), 1))
	}
}

// marshal encodes st without size limit.
func (st served) marshal() []byte {
	b := []byte{stateVersion}
	b = binary.AppendUvarint(b, uint64(len(st)))
	for _, fid := range slices.Sorted(maps.Keys(st)) {
		b = binary.AppendUvarint(b, uint64(len(fid)))
		b = append(b, fid...)
		list := st[fid]
		b = binary.AppendUvarint(b, uint64(len(list)))
		var prev int64
		for _, sp := range list {
			b = binary.AppendUvarint(b, uint64(sp.start-prev))   //nolint:gosec // G115: spans are sorted from 0, differences are positive
			b = binary.AppendUvarint(b, uint64(sp.end-sp.start)) //nolint:gosec // G115: start < end
			prev = sp.end
		}
	}
	return b
}

// drop removes the k shortest spans of st (all of them when there are
// fewer; ties broken by file ID then position), and the files left without
// span.
func (st served) drop(k int) {
	type ref struct {
		fid    string
		idx    int
		length int64
	}
	var refs []ref
	for fid, list := range st {
		for i, sp := range list {
			refs = append(refs, ref{fid: fid, idx: i, length: sp.end - sp.start})
		}
	}
	slices.SortFunc(refs, func(a, b ref) int {
		if c := cmp.Compare(a.length, b.length); c != 0 {
			return c
		}
		if c := cmp.Compare(a.fid, b.fid); c != 0 {
			return c
		}
		return cmp.Compare(a.idx, b.idx)
	})
	gone := map[string]map[int]bool{}
	for _, r := range refs[:min(k, len(refs))] {
		if gone[r.fid] == nil {
			gone[r.fid] = map[int]bool{}
		}
		gone[r.fid][r.idx] = true
	}
	for fid, idx := range gone {
		var kept []span
		for i, sp := range st[fid] {
			if !idx[i] {
				kept = append(kept, sp)
			}
		}
		if len(kept) == 0 {
			delete(st, fid)
		} else {
			st[fid] = kept
		}
	}
}

// stateReader reads the varints of an encoded state.
type stateReader struct {
	b   []byte
	bad bool
}

// next returns the next varint, at most limit and in its shortest form (so
// that an encoding is canonical); otherwise, or past the end, it marks the
// reader bad and returns 0.
func (r *stateReader) next(limit uint64) uint64 {
	if r.bad {
		return 0
	}
	v, n := binary.Uvarint(r.b)
	if n <= 0 || v > limit || n != len(binary.AppendUvarint(nil, v)) {
		r.bad = true
		return 0
	}
	r.b = r.b[n:]
	return v
}

// decodeServed decodes an encoded state. It returns errCorruptState unless
// b is a well-formed, canonical version 1 state (as marshal writes it):
// valid file IDs in strictly ascending order, spans sorted, disjoint,
// non-adjacent and non-empty, shortest varints, no trailing bytes.
func decodeServed(b []byte) (served, error) {
	if len(b) == 0 || b[0] != stateVersion {
		return nil, errCorruptState
	}
	r := &stateReader{b: b[1:]}
	n := r.next(storage.MaxStateSize)
	st := make(served, n)
	prevID := ""
	for range n {
		l := r.next(storage.MaxStateSize)
		if r.bad || uint64(len(r.b)) < l {
			return nil, errCorruptState
		}
		fid := string(r.b[:l])
		r.b = r.b[l:]
		if fid <= prevID || !id.Valid(id.File, fid) {
			return nil, errCorruptState
		}
		prevID = fid
		count := r.next(storage.MaxStateSize)
		var (
			list []span
			prev int64
		)
		for i := range count {
			gap := r.next(math.MaxInt64)
			length := r.next(math.MaxInt64)
			if r.bad || length == 0 || (i > 0 && gap == 0) || gap > uint64(math.MaxInt64-prev) {
				return nil, errCorruptState
			}
			start := prev + int64(gap)                //nolint:gosec // G115: bounded above
			if length > uint64(math.MaxInt64-start) { //nolint:gosec // G115: start is not negative
				return nil, errCorruptState
			}
			prev = start + int64(length) //nolint:gosec // G115: bounded above
			list = append(list, span{start: start, end: prev})
		}
		st[fid] = list
	}
	if r.bad || len(r.b) != 0 {
		return nil, errCorruptState
	}
	return st, nil
}
