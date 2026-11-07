package tte2

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	// MaxValidatorStateSize is the largest size of a Validator state produced
	// by MarshalBinary.
	MaxValidatorStateSize = validatorFixedSize + HeaderSize
	// validatorStateVersion is the first byte of a Validator state.
	validatorStateVersion = 1
	// validatorFixedSize is the size of a Validator state without its header
	// prefix: version, declared size and offset.
	validatorFixedSize = 1 + 8 + 8
)

// Validator checks, without the key, that an incoming upload can be a TTE2
// stream of the size declared by the client. The server calls Check on every
// received slice before writing it, and refuses the slice when Check fails.
//
// It verifies the header (magic, version, kind, reserved bytes, chunk size)
// byte by byte as it arrives, then that the declared size is exactly a valid
// stream size for the chunk size (ValidSize), and refuses any byte beyond the
// declared size. It cannot authenticate the chunks: a client that forges a
// valid header and random chunks passes (the recipient's Reader then fails
// with ErrAuth).
//
// A Validator keeps at most the first HeaderSize bytes of the stream. Its state
// survives a restart through MarshalBinary and UnmarshalBinary, so a resumed
// upload continues at Offset. A Validator is not safe for concurrent use.
type Validator struct {
	declared int64
	offset   int64
	prefix   [HeaderSize]byte // the first min(offset, HeaderSize) bytes
}

// NewValidator returns a Validator for a stream of declaredSize bytes, at
// offset 0. A declared size below MinFileSize is ErrFormat.
func NewValidator(declaredSize int64) (*Validator, error) {
	if declaredSize < MinFileSize {
		return nil, fmt.Errorf("%w: declared size %d below %d", ErrFormat, declaredSize, MinFileSize)
	}
	return &Validator{declared: declaredSize}, nil
}

// Check validates p, the bytes following Offset, before the caller stores
// them. It is atomic: on success the whole of p is accepted and Offset
// advances by len(p); on error (wrapping ErrFormat, and also ErrBadHeader for
// a header field) nothing is accepted and the Validator is unchanged. An empty
// p is always accepted.
func (v *Validator) Check(p []byte) error {
	if v.declared < MinFileSize {
		return fmt.Errorf("%w: validator not initialized", ErrFormat)
	}
	if len(p) == 0 {
		return nil
	}
	if int64(len(p)) > v.declared-v.offset {
		return fmt.Errorf("%w: data beyond the declared size %d", ErrFormat, v.declared)
	}
	if v.offset < HeaderSize {
		var pre [HeaderSize]byte
		have := int(v.offset)
		copy(pre[:], v.prefix[:have])
		n := copy(pre[have:], p)
		if err := v.checkPrefix(pre[:have+n]); err != nil {
			return err
		}
		v.prefix = pre
	}
	v.offset += int64(len(p))
	return nil
}

// checkPrefix validates a header prefix against the declared size.
func (v *Validator) checkPrefix(pre []byte) error {
	if err := checkHeaderPrefix(pre); err != nil {
		return fmt.Errorf("%w: %w", ErrFormat, err)
	}
	if c := prefixChunkSize(pre); c != 0 {
		if !ValidSize(v.declared, c) {
			return fmt.Errorf("%w: declared size %d is not a valid stream size for chunk size %d", ErrFormat, v.declared, c)
		}
	}
	return nil
}

// Offset returns the number of bytes accepted so far.
func (v *Validator) Offset() int64 { return v.offset }

// DeclaredSize returns the declared stream size.
func (v *Validator) DeclaredSize() int64 { return v.declared }

// ChunkSize returns the chunk size of the header, or 0 while it is not yet
// known (fewer than 12 bytes accepted).
func (v *Validator) ChunkSize() int {
	if v.offset < 12 {
		return 0
	}
	return int(binary.BigEndian.Uint32(v.prefix[8:12]))
}

// Complete reports whether the whole declared size has been accepted.
func (v *Validator) Complete() bool { return v.declared >= MinFileSize && v.offset == v.declared }

// MarshalBinary implements encoding.BinaryMarshaler. The state is at most
// MaxValidatorStateSize bytes:
//
//	version (1) | declared size (u64 BE) | offset (u64 BE) | first min(offset, 32) bytes
func (v *Validator) MarshalBinary() ([]byte, error) {
	n := min(v.offset, HeaderSize)
	b := make([]byte, validatorFixedSize, validatorFixedSize+n)
	b[0] = validatorStateVersion
	binary.BigEndian.PutUint64(b[1:9], uint64(v.declared)) //nolint:gosec // G115: declared is never negative (NewValidator, UnmarshalBinary).
	binary.BigEndian.PutUint64(b[9:17], uint64(v.offset))  //nolint:gosec // G115: offset is in [0, declared].
	return append(b, v.prefix[:n]...), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler. It decodes strictly
// (version, sizes, exact length) and re-validates the header prefix; any
// violation is ErrInvalidState and leaves v unchanged.
func (v *Validator) UnmarshalBinary(b []byte) error {
	if len(b) < validatorFixedSize || b[0] != validatorStateVersion {
		return fmt.Errorf("%w: bad version or length", ErrInvalidState)
	}
	declared := binary.BigEndian.Uint64(b[1:9])
	offset := binary.BigEndian.Uint64(b[9:17])
	if declared > math.MaxInt64 || declared < MinFileSize || offset > declared {
		return fmt.Errorf("%w: bad sizes", ErrInvalidState)
	}
	prefix := b[validatorFixedSize:]
	if uint64(len(prefix)) != min(offset, HeaderSize) {
		return fmt.Errorf("%w: bad length", ErrInvalidState)
	}
	fresh := Validator{declared: int64(declared)}
	if err := fresh.Check(prefix); err != nil {
		return fmt.Errorf("%w: %w", ErrInvalidState, err)
	}
	fresh.offset = int64(offset) //nolint:gosec // G115: offset <= declared <= math.MaxInt64.
	*v = fresh
	return nil
}
