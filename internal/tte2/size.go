package tte2

// CiphertextSize returns the size of the stream that encrypts plain bytes
// with chunk size chunk:
//
//	HeaderSize + plain + TagSize * n, with n = max(1, ceil(plain / chunk))
//
// It returns -1 for a negative plain, an invalid chunk size or a plaintext
// that would need more than MaxChunks chunks.
func CiphertextSize(plain int64, chunk int) int64 {
	if plain < 0 || !ValidChunkSize(chunk) {
		return -1
	}
	c := int64(chunk)
	if plain > MaxChunks*c {
		return -1
	}
	n := max(1, (plain+c-1)/c)
	return HeaderSize + plain + TagSize*n
}

// PlaintextSize returns the plaintext size of a stream of total bytes with
// chunk size chunk, and whether total is a valid stream size:
//
//	total = HeaderSize + (n-1)(chunk+TagSize) + (r+TagSize)
//
// with 1 <= n <= MaxChunks and r, the plaintext size of the final chunk, in
// [1, chunk], or r = 0 only when n = 1 (empty file).
func PlaintextSize(total int64, chunk int) (int64, bool) {
	if total < MinFileSize || !ValidChunkSize(chunk) {
		return 0, false
	}
	c := int64(chunk)
	block := c + TagSize
	body := total - HeaderSize
	q, rem := body/block, body%block
	var n, plain int64
	switch {
	case rem == 0:
		n, plain = q, q*c
	case rem == TagSize && q == 0:
		n, plain = 1, 0
	case rem > TagSize:
		n, plain = q+1, q*c+rem-TagSize
	default:
		return 0, false
	}
	if n > MaxChunks {
		return 0, false
	}
	return plain, true
}

// ValidSize reports whether total is the size of a valid stream with chunk
// size chunk (see PlaintextSize).
func ValidSize(total int64, chunk int) bool {
	_, ok := PlaintextSize(total, chunk)
	return ok
}
