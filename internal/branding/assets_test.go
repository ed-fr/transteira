package branding

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/jpeg"
	"image/png"
	"regexp"
	"testing"
	"time"
)

// defaultBackgroundSHA256 is the digest of the default background before the
// generator was shared with the presets: the refactoring must not change it.
const defaultBackgroundSHA256 = "1245362dbf165f4a9b777288eb6a89a75d71b13bbb9e6543c1e506e246daba42"

func TestDefaultBackgroundBytesUnchanged(t *testing.T) {
	t.Parallel()
	sum := sha256.Sum256(DefaultBackground().Data)
	if got := hex.EncodeToString(sum[:]); got != defaultBackgroundSHA256 {
		t.Errorf("default background sha256 = %s, want %s", got, defaultBackgroundSHA256)
	}
}

func TestKindsAsset(t *testing.T) {
	t.Parallel()
	cases := []struct {
		kind        Kind
		name        string
		contentType string
		favicon     bool
		uploadable  bool
	}{
		{KindLogo, "logo", ContentTypePNG, false, true},
		{KindBackground, "background", ContentTypeJPEG, false, true},
		{KindFavicon, "favicon", ContentTypeICO, true, false},
		{KindFavicon32, "favicon-32", ContentTypePNG, true, false},
		{KindAppleTouchIcon, "apple-touch-icon", ContentTypePNG, true, false},
	}
	for _, tc := range cases {
		if got := tc.kind.String(); got != tc.name {
			t.Errorf("%d String() = %q, want %q", tc.kind, got, tc.name)
		}
		if got := tc.kind.ContentType(); got != tc.contentType {
			t.Errorf("%s ContentType() = %q, want %q", tc.name, got, tc.contentType)
		}
		if got := tc.kind.IsFavicon(); got != tc.favicon {
			t.Errorf("%s IsFavicon() = %v", tc.name, got)
		}
		if got, err := ParseAsset(tc.name); err != nil || got != tc.kind {
			t.Errorf("ParseAsset(%q) = %v, %v", tc.name, got, err)
		}
		got, err := ParseKind(tc.name)
		if tc.uploadable && (err != nil || got != tc.kind) {
			t.Errorf("ParseKind(%q) = %v, %v", tc.name, got, err)
		}
		if !tc.uploadable && !errors.Is(err, ErrUnknownKind) {
			t.Errorf("ParseKind(%q) err = %v, want ErrUnknownKind", tc.name, err)
		}
		if !tc.uploadable && tc.kind.MaxBytes() != 0 {
			t.Errorf("%s has an upload limit", tc.name)
		}
	}
	for _, s := range []string{"", "Logo", "favicon.ico", "icon", "../logo"} {
		if _, err := ParseAsset(s); !errors.Is(err, ErrUnknownKind) {
			t.Errorf("ParseAsset(%q) err = %v", s, err)
		}
	}
	if Kind(0).String() != "" || Kind(0).ContentType() != "" || Kind(0).IsFavicon() {
		t.Error("the zero kind is not unknown")
	}
	want := []Kind{KindFavicon, KindFavicon32, KindAppleTouchIcon}
	got := FaviconKinds()
	if len(got) != len(want) {
		t.Fatalf("FaviconKinds() = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("FaviconKinds()[%d] = %v, want %v", i, got[i], want[i])
		}
	}
}

// logoPNG builds a PNG logo of w x h filled with an opaque gradient.
func logoPNG(t testing.TB, w, h int) []byte {
	t.Helper()
	img := image.NewNRGBA(image.Rect(0, 0, w, h))
	for y := range h {
		for x := range w {
			img.SetNRGBA(x, y, color.NRGBA{R: 0xC0, G: uint8(x * 255 / max(w, 1)), B: 0x20, A: 0xFF})
		}
	}
	return encodePNG(t, img)
}

// icoEntry is one parsed ICONDIRENTRY.
type icoEntry struct {
	w, h, colors, reserved int
	planes, bits           int
	length, offset         int
}

// parseICO is a small ICO reader that validates the container and returns
// its entries and the decoded PNG payloads.
func parseICO(t testing.TB, data []byte) (entries []icoEntry, images []image.Image) {
	t.Helper()
	le := binary.LittleEndian
	if len(data) < 6 {
		t.Fatalf("ICO too short: %d", len(data))
	}
	if r, typ := le.Uint16(data[0:]), le.Uint16(data[2:]); r != 0 || typ != 1 {
		t.Fatalf("ICONDIR reserved=%d type=%d", r, typ)
	}
	n := int(le.Uint16(data[4:]))
	next := 6 + 16*n
	for i := range n {
		e := data[6+16*i:]
		ent := icoEntry{
			w: int(e[0]), h: int(e[1]), colors: int(e[2]), reserved: int(e[3]),
			planes: int(le.Uint16(e[4:])), bits: int(le.Uint16(e[6:])),
			length: int(le.Uint32(e[8:])), offset: int(le.Uint32(e[12:])),
		}
		if ent.reserved != 0 || ent.colors != 0 || ent.planes != 1 || ent.bits != 32 {
			t.Fatalf("entry %d = %+v", i, ent)
		}
		if ent.offset != next || ent.offset+ent.length > len(data) {
			t.Fatalf("entry %d offset/length %+v for %d bytes (next %d)", i, ent, len(data), next)
		}
		next += ent.length
		img, err := png.Decode(bytes.NewReader(data[ent.offset : ent.offset+ent.length]))
		if err != nil {
			t.Fatalf("entry %d payload: %v", i, err)
		}
		if b := img.Bounds(); b.Dx() != ent.w || b.Dy() != ent.h {
			t.Fatalf("entry %d says %dx%d, payload is %dx%d", i, ent.w, ent.h, b.Dx(), b.Dy())
		}
		entries = append(entries, ent)
		images = append(images, img)
	}
	if next != len(data) {
		t.Fatalf("ICO has %d bytes, entries cover %d", len(data), next)
	}
	return entries, images
}

// checkFavicons validates the three icons of f.
func checkFavicons(t testing.TB, f Favicons) {
	t.Helper()
	entries, _ := parseICO(t, f.ICO.Data)
	if len(entries) != 3 || entries[0].w != 16 || entries[1].w != 32 || entries[2].w != 48 {
		t.Fatalf("ICO entries = %+v", entries)
	}
	if f.ICO.ContentType != ContentTypeICO || f.ICO.Width != 48 || f.ICO.Height != 48 {
		t.Errorf("ICO image = %s %dx%d", f.ICO.ContentType, f.ICO.Width, f.ICO.Height)
	}
	sum := sha256.Sum256(f.ICO.Data)
	if f.ICO.ETag != `"`+hex.EncodeToString(sum[:])+`"` {
		t.Errorf("ICO ETag = %s", f.ICO.ETag)
	}
	for _, c := range []struct {
		img  Image
		side int
	}{{f.PNG32, 32}, {f.PNG180, 180}} {
		if c.img.ContentType != ContentTypePNG || c.img.Width != c.side || c.img.Height != c.side {
			t.Errorf("PNG image = %s %dx%d", c.img.ContentType, c.img.Width, c.img.Height)
		}
		checkOutput(t, c.img)
	}
}

func TestGenerateFavicons(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		w, h int
	}{
		{"wide", 400, 100},
		{"tall", 90, 300},
		{"square", 64, 64},
		{"tiny", 1, 1},
		{"large", 512, 512},
		{"max", MaxLogoSide, 100},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f, err := GenerateFavicons(context.Background(), logoPNG(t, tc.w, tc.h))
			if err != nil {
				t.Fatal(err)
			}
			checkFavicons(t, f)
			for _, k := range FaviconKinds() {
				if img, ok := f.Get(k); !ok || img.ContentType != k.ContentType() {
					t.Errorf("Get(%v) = %s, %v", k, img.ContentType, ok)
				}
			}
			for _, k := range []Kind{KindLogo, KindBackground, 0} {
				if _, ok := f.Get(k); ok {
					t.Errorf("Get(%v) = true", k)
				}
			}
		})
	}
}

func TestGenerateFaviconsPadding(t *testing.T) {
	t.Parallel()
	alpha := func(img image.Image, x, y int) uint8 {
		return color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA).A
	}
	f, err := GenerateFavicons(context.Background(), logoPNG(t, 400, 100))
	if err != nil {
		t.Fatal(err)
	}
	img, err := png.Decode(bytes.NewReader(f.PNG180.Data))
	if err != nil {
		t.Fatal(err)
	}
	// A wide logo is centered: transparent bands above and below, opaque
	// center.
	if a, b, c := alpha(img, 90, 2), alpha(img, 90, 177), alpha(img, 90, 90); a != 0 || b != 0 || c != 0xFF {
		t.Errorf("alpha top=%d bottom=%d center=%d", a, b, c)
	}
	// A tall logo is padded on the sides.
	f, err = GenerateFavicons(context.Background(), logoPNG(t, 90, 300))
	if err != nil {
		t.Fatal(err)
	}
	img, _ = png.Decode(bytes.NewReader(f.PNG180.Data))
	if a, b := alpha(img, 2, 90), alpha(img, 90, 90); a != 0 || b != 0xFF {
		t.Errorf("alpha left=%d center=%d", a, b)
	}
}

func TestGenerateFaviconsErrors(t *testing.T) {
	t.Parallel()
	good := logoPNG(t, 32, 32)
	// A valid header followed by a truncated body: the config decodes, the
	// pixels do not.
	truncated := good[:len(good)-30]
	jpg := encodeJPEGT(t, image.NewRGBA(image.Rect(0, 0, 8, 8)))
	cases := []struct {
		name string
		data []byte
		want error
	}{
		{"jpeg", jpg, ErrInvalid},
		{"empty", nil, ErrInvalid},
		{"garbage", []byte("not an image"), ErrInvalid},
		{"truncated", truncated, ErrInvalid},
		{"oversize", pngFile(t, MaxLogoSide+1, 8, 8, 0, false, nil), ErrTooLarge},
	}
	for _, tc := range cases {
		if _, err := GenerateFavicons(context.Background(), tc.data); !errors.Is(err, tc.want) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
	}
}

func TestGenerateFaviconsContext(t *testing.T) {
	// Not parallel: it holds the process-wide decoding slot.
	good := logoPNG(t, 32, 32)
	decodeSlots <- struct{}{}
	defer func() { <-decodeSlots }()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := GenerateFavicons(ctx, good); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("err = %v, want deadline exceeded", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	cancel()
	if _, err := GenerateFavicons(ctx, good); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v, want canceled", err)
	}
}

func TestDefaultFavicon(t *testing.T) {
	t.Parallel()
	for _, k := range FaviconKinds() {
		img, ok := DefaultFavicon(k)
		if !ok || img.ContentType != k.ContentType() {
			t.Fatalf("DefaultFavicon(%v) = %s, %v", k, img.ContentType, ok)
		}
		// Deterministic, and a fresh copy each time.
		again, _ := DefaultFavicon(k)
		if again.ETag != img.ETag || !bytes.Equal(again.Data, img.Data) {
			t.Errorf("DefaultFavicon(%v) is not stable", k)
		}
		kept := bytes.Clone(img.Data)
		img.Data[len(img.Data)-1] ^= 0xFF
		img.Data[0] ^= 0xFF
		if third, _ := DefaultFavicon(k); !bytes.Equal(third.Data, kept) {
			t.Errorf("DefaultFavicon(%v) shares its data", k)
		}
	}
	f := Favicons{ICO: mustDefault(t, KindFavicon), PNG32: mustDefault(t, KindFavicon32), PNG180: mustDefault(t, KindAppleTouchIcon)}
	checkFavicons(t, f)
	for _, k := range []Kind{KindLogo, KindBackground, 0} {
		if _, ok := DefaultFavicon(k); ok {
			t.Errorf("DefaultFavicon(%v) = true", k)
		}
	}
	// The icon is a blue square with a white T and transparent corners.
	img, err := png.Decode(bytes.NewReader(f.PNG180.Data))
	if err != nil {
		t.Fatal(err)
	}
	px := func(x, y int) color.NRGBA { return color.NRGBAModel.Convert(img.At(x, y)).(color.NRGBA) }
	if c := px(0, 0); c.A != 0 {
		t.Errorf("corner = %+v, want transparent", c)
	}
	if c := px(20, 90); c != (color.NRGBA{R: 0x1D, G: 0x4E, B: 0xD8, A: 0xFF}) {
		t.Errorf("background = %+v", c)
	}
	// Stem of the T, at (16, 17) in the 32-unit viewBox.
	if c := px(90, 95); c != (color.NRGBA{R: 0xFF, G: 0xFF, B: 0xFF, A: 0xFF}) {
		t.Errorf("stem = %+v", c)
	}
}

// mustDefault returns the built-in icon of kind k.
func mustDefault(t testing.TB, k Kind) Image {
	t.Helper()
	img, ok := DefaultFavicon(k)
	if !ok {
		t.Fatalf("no default favicon %v", k)
	}
	return img
}

func TestPresets(t *testing.T) {
	t.Parallel()
	idPattern := regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	list := Presets()
	wantIDs := []string{"default", "aurora", "ocean", "forest", "sunset", "dusk", "sand", "slate"}
	if len(list) != len(wantIDs) || list[0].ID != DefaultPresetID {
		t.Fatalf("Presets() = %+v", list)
	}
	seen := map[string]bool{}
	for i, p := range list {
		if p.ID != wantIDs[i] {
			t.Errorf("preset %d = %q, want %q", i, p.ID, wantIDs[i])
		}
		if seen[p.ID] || !idPattern.MatchString(p.ID) {
			t.Errorf("preset id %q duplicate or malformed", p.ID)
		}
		seen[p.ID] = true
		if p.Labels["en"] == "" || p.Labels["fr"] == "" || len(p.Labels) != 2 {
			t.Errorf("preset %q labels = %v", p.ID, p.Labels)
		}
		if !ValidPreset(p.ID) {
			t.Errorf("ValidPreset(%q) = false", p.ID)
		}
	}
	for _, id := range []string{"", "../x", "Default", "default ", "unknown", "aurora/"} {
		if ValidPreset(id) {
			t.Errorf("ValidPreset(%q) = true", id)
		}
	}
	// Presets returns a deep copy.
	list[0].Labels["en"] = "changed"
	list[1].ID = "changed"
	if again := Presets(); again[0].Labels["en"] != "Default" || again[1].ID != "aurora" {
		t.Error("Presets shares its state")
	}
}

func TestPresetBackgrounds(t *testing.T) {
	t.Parallel()
	etags := map[string]string{}
	for _, p := range Presets() {
		start := time.Now()
		img, ok := PresetBackground(p.ID)
		t.Logf("%s generated in %v", p.ID, time.Since(start))
		if !ok {
			t.Fatalf("PresetBackground(%q) = false", p.ID)
		}
		dec, err := jpeg.Decode(bytes.NewReader(img.Data))
		if err != nil {
			t.Fatalf("%s: %v", p.ID, err)
		}
		if b := dec.Bounds(); b.Dx() != 1920 || b.Dy() != 1080 || img.Width != 1920 || img.Height != 1080 {
			t.Errorf("%s is %dx%d", p.ID, b.Dx(), b.Dy())
		}
		if img.ContentType != ContentTypeJPEG {
			t.Errorf("%s content type = %s", p.ID, img.ContentType)
		}
		checkOutput(t, img)
		if other, dup := etags[img.ETag]; dup {
			t.Errorf("%s and %s are identical", p.ID, other)
		}
		etags[img.ETag] = p.ID
		// Deterministic: same bytes twice, and a fresh render too.
		again, _ := PresetBackground(p.ID)
		if !bytes.Equal(again.Data, img.Data) {
			t.Errorf("%s is not stable", p.ID)
		}
		if d := lookupPreset(p.ID); p.ID != DefaultPresetID {
			if fresh := d.spec.render(); fresh.ETag != img.ETag {
				t.Errorf("%s is not reproducible", p.ID)
			}
		}
		// Mutation isolation.
		img.Data[len(img.Data)/2] ^= 0xFF
		if third, _ := PresetBackground(p.ID); !bytes.Equal(third.Data, again.Data) {
			t.Errorf("%s shares its data", p.ID)
		}
	}
	def, _ := PresetBackground(DefaultPresetID)
	if !bytes.Equal(def.Data, DefaultBackground().Data) {
		t.Error("the default preset differs from DefaultBackground")
	}
	for _, id := range []string{"nope", ""} {
		if _, ok := PresetBackground(id); ok {
			t.Errorf("PresetBackground(%q) = true", id)
		}
	}
}

func TestBackgroundFor(t *testing.T) {
	t.Parallel()
	def := DefaultBackground()
	for _, id := range []string{"", "unknown", "../etc"} {
		if got := BackgroundFor(id); got.ETag != def.ETag {
			t.Errorf("BackgroundFor(%q) is not the default", id)
		}
	}
	want, _ := PresetBackground("ocean")
	if got := BackgroundFor("ocean"); got.ETag != want.ETag || got.ETag == def.ETag {
		t.Error("BackgroundFor(ocean) is not the ocean preset")
	}
}

func TestBuildICO(t *testing.T) {
	t.Parallel()
	ico := buildICO([]icoImage{{16, []byte("a")}, {32, []byte("bc")}})
	// 6 header + 2 x 16 entries + 3 payload bytes.
	if len(ico) != 6+32+3 || binary.LittleEndian.Uint16(ico[4:]) != 2 {
		t.Fatalf("ico = % x", ico)
	}
	if got := binary.LittleEndian.Uint32(ico[6+16+12:]); got != 6+32+1 {
		t.Errorf("second offset = %d", got)
	}
}
