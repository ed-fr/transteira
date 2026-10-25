package bigfile

import uploadengine "github.com/ed-fr/transteira/internal/upload"

// CheckpointEvery is the checkpoint period of the server: within a PATCH it
// makes its progress durable every 64 MiB (and at the end of the request).
// It is not configurable through the environment.
const CheckpointEvery int64 = uploadengine.DefaultCheckpointEvery

// minCutSpan is the smallest number of bytes the interrupted PATCH sends so
// that the server checkpoints inside it before the cut: one checkpoint
// period plus a margin.
const minCutSpan = CheckpointEvery + 1<<20

// CutPlan places the interrupted PATCH of an upload.
type CutPlan struct {
	// Start is the offset of the interrupted PATCH: the regular PATCHes
	// cover [0, Start) beforehand, in chunks.
	Start int64
	// At is the offset after which the PATCH is cut: the bytes
	// [Start, At) are sent, then the connection is closed abruptly.
	At int64
	// Checkpoint reports whether the PATCH sends enough bytes for the
	// server to checkpoint inside it: the client then waits until HEAD
	// shows progress past Start before cutting, and the resume offset must
	// be past Start.
	Checkpoint bool
}

// PlanCut places the cut of an upload of size bytes sent in chunk-byte
// PATCHes at the fraction frac of the file (clamped into [1, size-1]). The
// interrupted PATCH starts on a chunk boundary at least minCutSpan bytes
// before the cut when the file allows it, so that the cut never falls on a
// boundary and the server checkpoints inside the request.
func PlanCut(size, chunk int64, frac float64) CutPlan {
	at := min(max(int64(frac*float64(size)), 1), size-1)
	if at < minCutSpan {
		return CutPlan{Start: 0, At: at}
	}
	start := (at - minCutSpan) / chunk * chunk
	return CutPlan{Start: start, At: at, Checkpoint: true}
}

// Chunks splits [from, to) into consecutive ranges of at most chunk bytes.
func Chunks(from, to, chunk int64) [][2]int64 {
	var out [][2]int64
	for off := from; off < to; off += chunk {
		out = append(out, [2]int64{off, min(off+chunk, to)})
	}
	return out
}
