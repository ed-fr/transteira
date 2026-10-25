package bigfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Report is the JSON report of a run, written to BIGFILE_REPORT pass or
// fail. Times are UTC (RFC 3339 with nanoseconds), so that the
// orchestration can match the phases with its memory samples.
type Report struct {
	Engine     string    `json:"engine,omitempty"`
	StartedAt  time.Time `json:"startedAt"`
	FinishedAt time.Time `json:"finishedAt"`
	Passed     bool      `json:"passed"`
	// Error is the first failure, empty on success.
	Error string `json:"error,omitempty"`

	Bytes      int64  `json:"bytes"`
	ChunkBytes int64  `json:"chunkBytes"`
	Seed       uint64 `json:"seed"`
	TenantHost string `json:"tenantHost"`
	TransferID string `json:"transferId,omitempty"`

	Upload   UploadReport   `json:"upload"`
	Download DownloadReport `json:"download"`
	// SHA256 holds the hexadecimal digests compared by the run.
	SHA256 Digests `json:"sha256"`
	// ScanStatus is the final scan status of the file.
	ScanStatus string `json:"scanStatus,omitempty"`

	Phases []Phase `json:"phases"`
}

// UploadReport describes the interrupted upload.
type UploadReport struct {
	// CutStart is the offset of the interrupted PATCH.
	CutStart int64 `json:"cutStart"`
	// CutAt is the offset reached by the client when it cut the connection.
	CutAt int64 `json:"cutAt"`
	// CheckpointSeen is the offset HEAD reported during the interrupted
	// PATCH, before the cut (0 when the plan expects no checkpoint).
	CheckpointSeen int64 `json:"checkpointSeen"`
	// ResumeOffset is the offset HEAD reported after the cut.
	ResumeOffset int64 `json:"resumeOffset"`
	// LostBytes is CutAt-ResumeOffset: bytes sent again after the cut.
	LostBytes int64 `json:"lostBytes"`
	// Patches is the number of PATCH requests, the interrupted one included.
	Patches int `json:"patches"`
}

// DownloadReport describes the interrupted download.
type DownloadReport struct {
	// CutAt is the number of bytes read before the first request was
	// abandoned; the Range request resumes from there.
	CutAt int64 `json:"cutAt"`
	// ETag is the entity tag of the file, sent back in If-Range.
	ETag string `json:"etag,omitempty"`
}

// Digests are the SHA-256 compared by the run (hexadecimal).
type Digests struct {
	Expected        string `json:"expected"`
	Server          string `json:"server,omitempty"`
	Page            string `json:"page,omitempty"`
	Download        string `json:"download,omitempty"`
	ResumedDownload string `json:"resumedDownload,omitempty"`
}

// Phase is one timed step of the run.
type Phase struct {
	Name    string    `json:"name"`
	Start   time.Time `json:"start"`
	End     time.Time `json:"end"`
	Seconds float64   `json:"seconds"`
	// Bytes moved during the phase (0 for steps without payload).
	Bytes int64 `json:"bytes"`
	// MiBPerSecond is Bytes/Seconds in MiB/s (0 without payload).
	MiBPerSecond float64 `json:"mibPerSecond"`
}

// String formats the phase for the test log.
func (p Phase) String() string {
	d := p.End.Sub(p.Start).Round(time.Millisecond)
	if p.Bytes == 0 {
		return fmt.Sprintf("%s: %s", p.Name, d)
	}
	return fmt.Sprintf("%s: %.1f MiB in %s (%.1f MiB/s)", p.Name, float64(p.Bytes)/(1<<20), d, p.MiBPerSecond)
}

// AddPhase records a phase from start to end that moved bytes, and returns
// it.
func (r *Report) AddPhase(name string, start, end time.Time, bytes int64) Phase {
	p := Phase{Name: name, Start: start.UTC(), End: end.UTC(), Seconds: end.Sub(start).Seconds(), Bytes: bytes}
	if bytes > 0 && p.Seconds > 0 {
		p.MiBPerSecond = float64(bytes) / (1 << 20) / p.Seconds
	}
	r.Phases = append(r.Phases, p)
	return p
}

// Write writes the report as indented JSON to path, creating its
// directory.
func (r *Report) Write(path string) error {
	b, _ := json.MarshalIndent(r, "", "  ") // plain fields and finite floats: never fails
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	if err := os.WriteFile(path, append(b, '\n'), 0o600); err != nil {
		return fmt.Errorf("report: %w", err)
	}
	return nil
}
