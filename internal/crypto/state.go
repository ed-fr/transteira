package crypto

import (
	"encoding/binary"
	"errors"
)

const (
	// stateMagic starts a serialized State.
	stateMagic = "TTCK"
	// stateVersion is the serialization version of a State.
	stateVersion = 1
	// stateFixedSize is the size of a serialized State without its tail:
	// magic, version, header, chunk count, extra length and tail length.
	stateFixedSize = 4 + 1 + HeaderSize + 4 + 4 + 4
)

// ErrBadState is returned for a malformed checkpoint state.
var ErrBadState = errors.New("crypto: invalid checkpoint state")

// State is a resumable checkpoint of a Writer (see Writer.Checkpoint and
// ResumeWriter). It holds no secret in clear: the incomplete tail and the
// caller's extra payload are sealed under the tail subkey of the file's DEK.
// A State is immutable.
type State struct {
	header   header
	chunks   uint32
	extraLen uint32
	tail     []byte // version | nonce | ciphertext of extra|pending, and tag
}

// UnmarshalState parses a State serialized by State.MarshalBinary. Parsing is
// strict: wrong magic or version, invalid header, inconsistent lengths or
// extra bytes return ErrBadState. The tail is authenticated later, by
// ResumeWriter.
func UnmarshalState(b []byte) (*State, error) {
	st := new(State)
	if err := st.UnmarshalBinary(b); err != nil {
		return nil, err
	}
	return st, nil
}

// MarshalBinary implements encoding.BinaryMarshaler.
func (s *State) MarshalBinary() ([]byte, error) {
	if s == nil {
		return nil, ErrBadState
	}
	b := make([]byte, 0, stateFixedSize+len(s.tail))
	b = append(b, stateMagic...)
	b = append(b, stateVersion)
	b = append(b, s.header[:]...)
	b = binary.BigEndian.AppendUint32(b, s.chunks)
	b = binary.BigEndian.AppendUint32(b, s.extraLen)
	b = binary.BigEndian.AppendUint32(b, u32(len(s.tail)))
	return append(b, s.tail...), nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler with the strict
// parsing of UnmarshalState. On error, s is left unchanged.
func (s *State) UnmarshalBinary(b []byte) error {
	if len(b) < stateFixedSize || string(b[:4]) != stateMagic || b[4] != stateVersion {
		return ErrBadState
	}
	var st State
	copy(st.header[:], b[5:5+HeaderSize])
	st.chunks = binary.BigEndian.Uint32(b[21:25])
	st.extraLen = binary.BigEndian.Uint32(b[25:29])
	if int64(binary.BigEndian.Uint32(b[29:33])) != int64(len(b)-stateFixedSize) {
		return ErrBadState
	}
	st.tail = append([]byte(nil), b[stateFixedSize:]...)
	if _, err := st.validate(); err != nil {
		return err
	}
	*s = st
	return nil
}

// validate checks the header and the tail framing and returns the chunk size.
func (s *State) validate() (int, error) {
	if s == nil {
		return 0, ErrBadState
	}
	chunkSize, err := s.header.chunkSize()
	if err != nil || s.extraLen > MaxCheckpointExtra || len(s.tail) == 0 || s.tail[0] != tailVersion {
		return 0, ErrBadState
	}
	pending := len(s.tail) - envelopeOverhead - int(s.extraLen)
	if pending < 0 || pending >= chunkSize {
		return 0, ErrBadState
	}
	return chunkSize, nil
}

// ChunkSize returns the plaintext chunk size of the file, or 0 for an invalid
// state.
func (s *State) ChunkSize() int {
	cs, _ := s.validate()
	return cs
}

// CiphertextSize returns the exact size the encrypted file must have to be
// resumed from this state: the header and the complete chunks. It returns -1
// for an invalid state.
func (s *State) CiphertextSize() int64 {
	cs, err := s.validate()
	if err != nil {
		return -1
	}
	return HeaderSize + int64(s.chunks)*int64(cs+tagSize)
}

// PlaintextSize returns the number of plaintext bytes covered by the state:
// the complete chunks plus the sealed tail (the extra payload excluded). This
// is the offset from which an upload resumes. It returns -1 for an invalid
// state.
func (s *State) PlaintextSize() int64 {
	cs, err := s.validate()
	if err != nil {
		return -1
	}
	return int64(s.chunks)*int64(cs) + int64(len(s.tail)-envelopeOverhead-int(s.extraLen))
}
