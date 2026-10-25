// Package seeded generates deterministic pseudo-random test contents of any
// size on the fly, so that the tests never store large files: the same seed
// always gives the same bytes, any slice of a stream can be regenerated from
// its offset without producing what precedes it, and the SHA-256 of a
// stream can be computed without keeping it.
//
// The stream is cut into blocks of BlockSize bytes; block i of seed s is the
// output of a ChaCha8 generator keyed by (s, i). Seeking to an offset
// therefore costs at most one block of generation, whatever the offset
// (a 20 GiB stream resumes at 8 GiB instantly).
//
// This is test data, never key material: the generator is deterministic on
// purpose and must not be used for anything security related.
package seeded

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math"
	"math/rand/v2" //nolint:depguard // deterministic test data generator, never used for security
)

// BlockSize is the number of bytes generated from one ChaCha8 key.
const BlockSize = 1 << 20

// domain fills the end of every block key, so that the streams of this
// package never coincide with another use of ChaCha8 seeded with small
// integers.
const domain = "tt-seeded-stream"

// blockKey returns the ChaCha8 key of the block index of seed.
func blockKey(seed uint64, index int64) [32]byte {
	var k [32]byte
	binary.LittleEndian.PutUint64(k[0:8], seed)
	binary.LittleEndian.PutUint64(k[8:16], uint64(index)) //nolint:gosec // index is never negative
	copy(k[16:], domain)
	return k
}

// reader produces the bytes [pos, end) of the stream of seed.
type reader struct {
	seed     uint64
	pos, end int64
	block    *rand.ChaCha8
	left     int64 // bytes left in the current block
}

// Read implements io.Reader. It never fails before io.EOF.
func (r *reader) Read(p []byte) (int, error) {
	if r.pos >= r.end {
		return 0, io.EOF
	}
	if r.left == 0 {
		r.startBlock()
	}
	n := min(int64(len(p)), r.left, r.end-r.pos)
	_, _ = r.block.Read(p[:n]) // ChaCha8.Read always fills p and returns nil
	r.pos += n
	r.left -= n
	return int(n), nil
}

// startBlock starts the block holding r.pos and skips its bytes before
// r.pos.
func (r *reader) startBlock() {
	r.block = rand.NewChaCha8(blockKey(r.seed, r.pos/BlockSize))
	skip := r.pos % BlockSize
	var scratch [32 << 10]byte
	for skip > 0 {
		n := min(skip, int64(len(scratch)))
		_, _ = r.block.Read(scratch[:n])
		skip -= n
	}
	r.left = BlockSize - r.pos%BlockSize
}

// Stream returns a reader of the first size bytes of the stream of seed. It
// panics when size is negative.
func Stream(seed uint64, size int64) io.Reader {
	return Range(seed, 0, size)
}

// Range returns a reader of the n bytes of the stream of seed starting at
// offset off: exactly the bytes [off, off+n) of Stream(seed, off+n). It
// panics when off or n is negative or when off+n overflows.
func Range(seed uint64, off, n int64) io.Reader {
	if off < 0 || n < 0 || n > math.MaxInt64-off {
		panic(fmt.Sprintf("seeded: invalid range offset %d length %d", off, n))
	}
	return &reader{seed: seed, pos: off, end: off + n}
}

// Bytes returns the first n bytes of the stream of seed, for contents small
// enough to be held in memory.
func Bytes(seed uint64, n int) []byte {
	b := make([]byte, n)
	_, _ = io.ReadFull(Stream(seed, int64(n)), b) // the reader never fails
	return b
}

// Sum returns the SHA-256 of the first size bytes of the stream of seed,
// computed in a single pass without storing them.
func Sum(seed uint64, size int64) [32]byte {
	h := sha256.New()
	r := Stream(seed, size)
	buf := make([]byte, 256<<10)
	for {
		n, err := r.Read(buf)
		h.Write(buf[:n])
		if err != nil { // io.EOF: the reader never fails otherwise
			break
		}
	}
	var s [32]byte
	h.Sum(s[:0])
	return s
}

// SumHex returns Sum in lower-case hexadecimal, the format of the API.
func SumHex(seed uint64, size int64) string {
	s := Sum(seed, size)
	return hex.EncodeToString(s[:])
}

// HashingReader computes the SHA-256 and counts the bytes of what is read
// through it.
type HashingReader struct {
	r io.Reader
	h hash.Hash
	n int64
}

// NewHashingReader returns a HashingReader reading from r.
func NewHashingReader(r io.Reader) *HashingReader {
	return &HashingReader{r: r, h: sha256.New()}
}

// Read implements io.Reader.
func (h *HashingReader) Read(p []byte) (int, error) {
	n, err := h.r.Read(p)
	h.h.Write(p[:n])
	h.n += int64(n)
	return n, err
}

// N returns the number of bytes read so far.
func (h *HashingReader) N() int64 { return h.n }

// Sum returns the SHA-256 of the bytes read so far.
func (h *HashingReader) Sum() [32]byte {
	var s [32]byte
	h.h.Sum(s[:0])
	return s
}

// Hex returns the lower-case hexadecimal SHA-256 of the bytes read so far.
func (h *HashingReader) Hex() string { return hex.EncodeToString(h.h.Sum(nil)) }
