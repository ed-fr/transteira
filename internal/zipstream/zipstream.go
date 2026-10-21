// Package zipstream writes the download ZIP archive of a transfer as a
// stream, in store mode (no compression), with a byte length known before the
// first byte is written so that the HTTP response carries an exact
// Content-Length.
//
// # Layout
//
// Each entry is written in order as a local file header, the file data, then
// a data descriptor carrying the CRC-32 computed on the fly; the central
// directory and the end records follow. The general purpose flags are always
// bit 3 (data descriptor) and bit 11 (UTF-8 names). Memory use is one fixed
// copy buffer plus one CRC per entry; no file is ever held in memory.
//
// By default (Format{} and the package level Size and Write) every entry uses
// ZIP64 records, even an empty one, and the archive always ends with the
// ZIP64 end of central directory record and locator: the size of an archive is
// then a simple formula of the name lengths and file sizes. A Format with a
// positive Zip64Threshold only uses ZIP64 where needed or requested, for the
// rare unzip tools that refuse ZIP64; Size stays exact in both modes.
//
// # Compatibility
//
// The ZIP64 records follow APPNOTE 6.3.x literally: a ZIP64 local header
// carries the ZIP64 extended information field with both sizes (zero, as they
// are unknown when the header is written) and 0xFFFFFFFF in the 32-bit size
// fields, so that streaming readers know the data descriptor holds 8-byte
// sizes; the central directory carries the real sizes and offset in the ZIP64
// field; the end of central directory record holds the 0xFFFF / 0xFFFFFFFF
// markers that send every reader to the ZIP64 end record.
//
// Known behavior of common tools with always-ZIP64 archives:
//
//   - Go archive/zip, 7-Zip, Info-ZIP unzip 6.0 (built with ZIP64 support, the
//     default of every current distribution), libarchive (bsdtar, the Windows
//     11 Explorer since 2023, many Linux file managers), Python zipfile and
//     Java java.util.zip read them, beyond 4 GiB and 65535 entries included.
//   - Windows Explorer (compressed folders) reads ZIP64 archives since
//     Windows Vista/7, including small entries flagged ZIP64.
//   - The macOS Archive Utility has a history of failures on ZIP64 archives
//     written with data descriptors, mostly beyond 4 GiB; "ditto -x -k",
//     the unzip command and The Unarchiver read them. A Format with
//     Zip64Threshold set to Zip64WhenNeeded produces a classic archive when
//     nothing exceeds the 32-bit limits, which avoids the issue for small
//     archives.
//
// Timestamps are stored as MS-DOS date and time (2-second resolution) of
// Entry.Modified converted to UTC; unzip tools display them as local time.
//
// # Names
//
// Entry names are expected to come from filename.ArchiveName (threats T-51
// and T-52). They are nevertheless validated again: valid UTF-8, at most
// 65535 bytes, no control character, no backslash, no colon (drive letters,
// NTFS alternate streams), components separated by "/" that are neither
// empty (no leading or trailing "/") nor "." or "..", and no two names equal
// case-insensitively.
package zipstream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"math"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Errors returned by Size and Write, wrapped with the index of the entry
// concerned.
var (
	// ErrInvalidName reports an entry name that does not pass validation.
	ErrInvalidName = errors.New("zipstream: invalid entry name")
	// ErrDuplicateName reports two entry names equal case-insensitively.
	ErrDuplicateName = errors.New("zipstream: duplicate entry name")
	// ErrNegativeSize reports an entry with a negative size.
	ErrNegativeSize = errors.New("zipstream: negative entry size")
	// ErrTooLarge reports an archive whose size does not fit in an int64.
	ErrTooLarge = errors.New("zipstream: archive too large")
	// ErrShortEntry reports an entry reader that ended before Entry.Size bytes.
	ErrShortEntry = errors.New("zipstream: entry reader yielded fewer bytes than its size")
	// ErrLongEntry reports an entry reader that yielded more than Entry.Size
	// bytes. The extra bytes are never written.
	ErrLongEntry = errors.New("zipstream: entry reader yielded more bytes than its size")
)

// Zip64WhenNeeded is the Zip64Threshold that only uses ZIP64 records where the
// 32-bit fields of the classic format cannot hold a value.
const Zip64WhenNeeded int64 = max32

// Record signatures, lengths and field values (APPNOTE 6.3.x).
const (
	localHeaderSig    = 0x04034b50
	dataDescriptorSig = 0x08074b50
	centralHeaderSig  = 0x02014b50
	zip64EndSig       = 0x06064b50
	zip64LocatorSig   = 0x07064b50
	endSig            = 0x06054b50

	localHeaderLen    = 30
	centralHeaderLen  = 46
	descriptorLen     = 16
	descriptor64Len   = 24
	localExtra64Len   = 4 + 16
	centralExtra64Len = 4 + 24
	offsetExtraLen    = 4 + 8
	zip64EndLen       = 56
	zip64LocatorLen   = 20
	endLen            = 22
	zip64EndsLen      = zip64EndLen + zip64LocatorLen + endLen

	max16 = 0xFFFF
	max32 = 0xFFFFFFFF

	zip64ExtraID   = 0x0001
	flags          = 1<<3 | 1<<11 // data descriptor, UTF-8 names
	methodStore    = 0
	versionClassic = 20
	versionZip64   = 45
	versionMadeBy  = 3<<8 | versionZip64 // Unix, APPNOTE 4.5
	externalAttrs  = 0o100644 << 16      // regular file, rw-r--r--

	maxNameLen = max16
	bufferSize = 64 << 10
	// maxEmptyReads bounds the successive (0, nil) reads tolerated from an
	// entry reader before giving up with io.ErrNoProgress.
	maxEmptyReads = 100
)

// Entry describes one file of the archive.
type Entry struct {
	// Name is the path of the file inside the archive, "/" separated.
	Name string
	// Size is the exact number of bytes the entry reader yields.
	Size int64
	// Modified is the modification time, stored in UTC with a 2-second
	// resolution and clamped to the MS-DOS range (1980 to 2107).
	Modified time.Time
}

// Format selects how ZIP64 records are used. The zero value uses them for
// every entry and always ends the archive with the ZIP64 end records.
type Format struct {
	// Zip64Threshold, when positive, makes only the entries of at least this
	// size use ZIP64 records; values above Zip64WhenNeeded act as
	// Zip64WhenNeeded, the limit of the classic format. The central directory
	// then stores a ZIP64 offset only for entries starting beyond 4 GiB, and
	// the ZIP64 end records are only written beyond 65534 entries or 4 GiB.
	// Zero or negative selects the always-ZIP64 layout.
	Zip64Threshold int64
}

// Size returns the exact byte length of the archive Write produces for
// entries with the default Format.
func Size(entries []Entry) (int64, error) {
	return Format{}.Size(entries)
}

// Write streams the archive of entries to w with the default Format. See
// Format.Write.
func Write(w io.Writer, entries []Entry, open func(i int) (io.Reader, error)) error {
	return Format{}.Write(w, entries, open)
}

// Size returns the exact byte length of the archive Write produces for
// entries, or an error if an entry is invalid (see the package documentation)
// or the archive would exceed math.MaxInt64 bytes.
func (f Format) Size(entries []Entry) (int64, error) {
	p, err := f.plan(entries)
	if err != nil {
		return 0, err
	}
	return p.total, nil
}

// Write streams the archive of entries to w: for each entry in order, it
// calls open(i), copies exactly entries[i].Size bytes from the returned
// reader while computing their CRC-32, then writes the central directory and
// the end records. The output length always equals f.Size(entries).
//
// If the reader returned by open also implements io.Closer, Write closes it
// once the entry is copied or has failed. Write stops at the first error:
// invalid entries (nothing is written), an error from open, from a reader or
// from w, or a reader yielding fewer (ErrShortEntry) or more (ErrLongEntry)
// bytes than the entry size. The output is then truncated and must be
// discarded.
func (f Format) Write(w io.Writer, entries []Entry, open func(i int) (io.Reader, error)) error {
	p, err := f.plan(entries)
	if err != nil {
		return err
	}
	crcs := make([]uint32, len(entries))
	buf := make([]byte, bufferSize)
	hdr := make([]byte, 0, centralHeaderLen+centralExtra64Len+256)

	for i, e := range entries {
		z := f.zip64(e.Size)
		hdr = appendLocalHeader(hdr[:0], e, z)
		if err := writeAll(w, hdr); err != nil {
			return err
		}
		crc, err := copyEntry(w, i, e.Size, open, buf)
		if err != nil {
			return fmt.Errorf("zipstream: entry %d: %w", i, err)
		}
		crcs[i] = crc
		hdr = appendDescriptor(hdr[:0], crc, e.Size, z)
		if err := writeAll(w, hdr); err != nil {
			return err
		}
	}

	var offset int64
	for i, e := range entries {
		hdr = f.appendCentralHeader(hdr[:0], e, crcs[i], offset)
		if err := writeAll(w, hdr); err != nil {
			return err
		}
		offset += f.localSpan(e)
	}
	return writeAll(w, appendEnd(hdr[:0], p, len(entries)))
}

// plan is the layout of an archive, computed before anything is written.
type plan struct {
	cdOffset int64 // offset of the central directory
	cdSize   int64 // length of the central directory
	total    int64 // length of the archive
	zip64End bool  // whether the ZIP64 end records are written
}

// plan validates entries and computes the layout of their archive.
func (f Format) plan(entries []Entry) (plan, error) {
	var p plan
	seen := make(map[string]struct{}, len(entries))
	for i, e := range entries {
		if err := validName(e.Name); err != nil {
			return plan{}, fmt.Errorf("zipstream: entry %d: %w", i, err)
		}
		key := strings.ToLower(e.Name)
		if _, dup := seen[key]; dup {
			return plan{}, fmt.Errorf("zipstream: entry %d: %w", i, ErrDuplicateName)
		}
		seen[key] = struct{}{}
		if e.Size < 0 {
			return plan{}, fmt.Errorf("zipstream: entry %d: %w", i, ErrNegativeSize)
		}
		// The central header length depends on the entry offset, which is
		// the running total before this entry.
		central := f.centralLen(e, p.cdOffset)
		local, ok := add(f.localLen(e), e.Size)
		if ok {
			p.cdOffset, ok = add(p.cdOffset, local)
		}
		if ok {
			p.cdSize, ok = add(p.cdSize, central)
		}
		if !ok {
			return plan{}, ErrTooLarge
		}
	}
	p.zip64End = f.Zip64Threshold <= 0 || len(entries) >= max16 ||
		p.cdOffset >= max32 || p.cdSize >= max32
	ends := int64(endLen)
	if p.zip64End {
		ends = zip64EndsLen
	}
	var ok bool
	p.total, ok = add(p.cdOffset, p.cdSize)
	if ok {
		p.total, ok = add(p.total, ends)
	}
	if !ok {
		return plan{}, ErrTooLarge
	}
	return p, nil
}

// add returns a+b for non-negative a and b, and false on overflow.
func add(a, b int64) (int64, bool) {
	if a > math.MaxInt64-b {
		return 0, false
	}
	return a + b, true
}

// zip64 reports whether an entry of the given size uses ZIP64 records.
func (f Format) zip64(size int64) bool {
	return f.Zip64Threshold <= 0 || size >= min(f.Zip64Threshold, max32)
}

// localLen returns the length of the local header and data descriptor of e.
func (f Format) localLen(e Entry) int64 {
	if f.zip64(e.Size) {
		return localHeaderLen + int64(len(e.Name)) + localExtra64Len + descriptor64Len
	}
	return localHeaderLen + int64(len(e.Name)) + descriptorLen
}

// localSpan returns the length of the local header, data and data descriptor
// of a validated entry.
func (f Format) localSpan(e Entry) int64 {
	return f.localLen(e) + e.Size
}

// centralLen returns the length of the central directory header of e when
// its local header starts at offset.
func (f Format) centralLen(e Entry, offset int64) int64 {
	n := centralHeaderLen + int64(len(e.Name))
	switch {
	case f.zip64(e.Size):
		n += centralExtra64Len
	case offset >= max32:
		n += offsetExtraLen
	}
	return n
}

// validName reports whether name is acceptable as an entry name.
func validName(name string) error {
	if name == "" || len(name) > maxNameLen || !utf8.ValidString(name) {
		return ErrInvalidName
	}
	for _, r := range name {
		if unicode.IsControl(r) || r == '\\' || r == ':' {
			return ErrInvalidName
		}
	}
	for part := range strings.SplitSeq(name, "/") {
		if part == "" || part == "." || part == ".." {
			return ErrInvalidName
		}
	}
	return nil
}

// copyEntry opens entry i and copies exactly size bytes of it to w, returning
// their CRC-32.
func copyEntry(w io.Writer, i int, size int64, open func(i int) (io.Reader, error), buf []byte) (crc uint32, err error) {
	r, err := open(i)
	if err != nil {
		return 0, err
	}
	if c, ok := r.(io.Closer); ok {
		defer func() {
			if cerr := c.Close(); err == nil && cerr != nil {
				crc, err = 0, cerr
			}
		}()
	}
	remaining := size
	empty := 0
	for {
		// Ask for one byte more than remains, to detect a reader that is
		// too long without writing its extra bytes.
		n := len(buf)
		if remaining < int64(n) {
			n = int(remaining) + 1
		}
		m, rerr := r.Read(buf[:n])
		if int64(m) > remaining {
			return 0, ErrLongEntry
		}
		if m > 0 {
			empty = 0
			crc = crc32.Update(crc, crc32.IEEETable, buf[:m])
			if err := writeAll(w, buf[:m]); err != nil {
				return 0, err
			}
			remaining -= int64(m)
		} else if rerr == nil {
			empty++
			if empty >= maxEmptyReads {
				return 0, io.ErrNoProgress
			}
		}
		if errors.Is(rerr, io.EOF) {
			if remaining > 0 {
				return 0, ErrShortEntry
			}
			return crc, nil
		}
		if rerr != nil {
			return 0, rerr
		}
	}
}

// writeAll writes p to w, turning a short write into io.ErrShortWrite.
func writeAll(w io.Writer, p []byte) error {
	n, err := w.Write(p)
	if err == nil && n != len(p) {
		err = io.ErrShortWrite
	}
	return err
}

// dosTime returns the MS-DOS date and time of t in UTC, clamped to the range
// the format can represent.
func dosTime(t time.Time) (date, clock uint16) {
	t = t.UTC()
	switch {
	case t.Year() < 1980:
		return 1<<5 | 1, 0 // 1980-01-01 00:00:00
	case t.Year() > 2107:
		return 127<<9 | 12<<5 | 31, 23<<11 | 59<<5 | 29 // 2107-12-31 23:59:58
	}
	date = uint16((t.Year()-1980)<<9 | int(t.Month())<<5 | t.Day()) //nolint:gosec // G115: year clamped to 1980-2107, fits 16 bits
	clock = uint16(t.Hour()<<11 | t.Minute()<<5 | t.Second()/2)     //nolint:gosec // G115: hour, minute, second fit 16 bits
	return date, clock
}

// le appends little-endian integers.
var le = binary.LittleEndian

// u32 returns v as a 32-bit field value, or the 0xFFFFFFFF marker when it
// does not fit.
func u32(v int64) uint32 {
	if v >= max32 {
		return max32
	}
	return uint32(v) //nolint:gosec // G115: 0 <= v < 0xFFFFFFFF
}

// u64 returns a non-negative int64 as a 64-bit field value.
func u64(v int64) uint64 {
	return uint64(v) //nolint:gosec // G115: sizes and offsets are validated non-negative
}

// nameLen returns the length of a validated name as a 16-bit field value.
func nameLen(name string) uint16 {
	return uint16(len(name)) //nolint:gosec // G115: validName bounds the length to 65535
}

// appendLocalHeader appends the local file header of e.
func appendLocalHeader(b []byte, e Entry, zip64 bool) []byte {
	date, clock := dosTime(e.Modified)
	version, size, extra := uint16(versionClassic), uint32(0), uint16(0)
	if zip64 {
		version, size, extra = versionZip64, max32, localExtra64Len
	}
	b = le.AppendUint32(b, localHeaderSig)
	b = le.AppendUint16(b, version)
	b = le.AppendUint16(b, flags)
	b = le.AppendUint16(b, methodStore)
	b = le.AppendUint16(b, clock)
	b = le.AppendUint16(b, date)
	b = le.AppendUint32(b, 0) // CRC-32, in the data descriptor
	b = le.AppendUint32(b, size)
	b = le.AppendUint32(b, size)
	b = le.AppendUint16(b, nameLen(e.Name))
	b = le.AppendUint16(b, extra)
	b = append(b, e.Name...)
	if zip64 {
		b = le.AppendUint16(b, zip64ExtraID)
		b = le.AppendUint16(b, 16)
		b = le.AppendUint64(b, 0) // uncompressed size, in the data descriptor
		b = le.AppendUint64(b, 0) // compressed size, in the data descriptor
	}
	return b
}

// appendDescriptor appends the data descriptor of an entry.
func appendDescriptor(b []byte, crc uint32, size int64, zip64 bool) []byte {
	b = le.AppendUint32(b, dataDescriptorSig)
	b = le.AppendUint32(b, crc)
	if zip64 {
		b = le.AppendUint64(b, u64(size))
		return le.AppendUint64(b, u64(size))
	}
	b = le.AppendUint32(b, u32(size))
	return le.AppendUint32(b, u32(size))
}

// appendCentralHeader appends the central directory header of e, whose local
// header starts at offset.
func (f Format) appendCentralHeader(b []byte, e Entry, crc uint32, offset int64) []byte {
	date, clock := dosTime(e.Modified)
	zip64 := f.zip64(e.Size)
	version, size, off := uint16(versionClassic), u32(e.Size), u32(offset)
	extra := uint16(0)
	switch {
	case zip64:
		version, size, off, extra = versionZip64, max32, max32, centralExtra64Len
	case off == max32:
		extra = offsetExtraLen
	}
	b = le.AppendUint32(b, centralHeaderSig)
	b = le.AppendUint16(b, versionMadeBy)
	b = le.AppendUint16(b, version)
	b = le.AppendUint16(b, flags)
	b = le.AppendUint16(b, methodStore)
	b = le.AppendUint16(b, clock)
	b = le.AppendUint16(b, date)
	b = le.AppendUint32(b, crc)
	b = le.AppendUint32(b, size)
	b = le.AppendUint32(b, size)
	b = le.AppendUint16(b, nameLen(e.Name))
	b = le.AppendUint16(b, extra)
	b = le.AppendUint16(b, 0) // comment length
	b = le.AppendUint16(b, 0) // disk number start
	b = le.AppendUint16(b, 0) // internal attributes
	b = le.AppendUint32(b, externalAttrs)
	b = le.AppendUint32(b, off)
	b = append(b, e.Name...)
	switch {
	case zip64:
		b = le.AppendUint16(b, zip64ExtraID)
		b = le.AppendUint16(b, 24)
		b = le.AppendUint64(b, u64(e.Size))
		b = le.AppendUint64(b, u64(e.Size))
		b = le.AppendUint64(b, u64(offset))
	case off == max32:
		b = le.AppendUint16(b, zip64ExtraID)
		b = le.AppendUint16(b, 8)
		b = le.AppendUint64(b, u64(offset))
	}
	return b
}

// appendEnd appends the end records of an archive of n entries laid out by p.
func appendEnd(b []byte, p plan, n int) []byte {
	records, cdSize, cdOffset := uint16(max16), uint32(max32), uint32(max32)
	if p.zip64End {
		zip64End := p.cdOffset + p.cdSize
		b = le.AppendUint32(b, zip64EndSig)
		b = le.AppendUint64(b, zip64EndLen-12) // size of the remaining record
		b = le.AppendUint16(b, versionMadeBy)
		b = le.AppendUint16(b, versionZip64)
		b = le.AppendUint32(b, 0) // number of this disk
		b = le.AppendUint32(b, 0) // disk of the central directory
		b = le.AppendUint64(b, u64(int64(n)))
		b = le.AppendUint64(b, u64(int64(n)))
		b = le.AppendUint64(b, u64(p.cdSize))
		b = le.AppendUint64(b, u64(p.cdOffset))

		b = le.AppendUint32(b, zip64LocatorSig)
		b = le.AppendUint32(b, 0) // disk of the ZIP64 end record
		b = le.AppendUint64(b, u64(zip64End))
		b = le.AppendUint32(b, 1) // total number of disks
	} else {
		// Without ZIP64 end records, plan guarantees that every value fits.
		records, cdSize, cdOffset = uint16(n), u32(p.cdSize), u32(p.cdOffset) //nolint:gosec // G115: n < 0xFFFF here
	}
	b = le.AppendUint32(b, endSig)
	b = le.AppendUint16(b, 0) // number of this disk
	b = le.AppendUint16(b, 0) // disk of the central directory
	b = le.AppendUint16(b, records)
	b = le.AppendUint16(b, records)
	b = le.AppendUint32(b, cdSize)
	b = le.AppendUint32(b, cdOffset)
	return le.AppendUint16(b, 0) // comment length
}
