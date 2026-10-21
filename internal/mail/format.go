package mail

import (
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/ed-fr/transteira/internal/i18n"
)

// nbsp separates a number from its unit, so that mail clients never wrap
// between them.
const nbsp = "\u00a0"

// sizeUnits are the binary size units of each language, from bytes up.
var sizeUnits = map[string][]string{
	i18n.French:  {"o", "Ko", "Mo", "Go", "To", "Po"},
	i18n.English: {"B", "KB", "MB", "GB", "TB", "PB"},
}

// FormatSize formats a size in bytes the way lang writes it, with binary
// multiples (1 KB = 1024 bytes, as file managers display them): "512 B",
// "1.5 MB", "20 GB" in English, "512 o", "1,5 Mo", "20 Go" in French. Values
// below 10 units keep one decimal, larger ones are rounded to the unit. An
// unsupported language uses English; a negative size is formatted as 0.
func FormatSize(lang string, n int64) string {
	units, ok := sizeUnits[lang]
	if !ok {
		units = sizeUnits[i18n.English]
	}
	if n < 1024 {
		return strconv.FormatInt(max(n, 0), 10) + nbsp + units[0]
	}
	v := float64(n)
	u := 0
	for v >= 1024 && u < len(units)-1 {
		v /= 1024
		u++
	}
	var s string
	if v < 10 {
		v = math.Round(v*10) / 10
		if v >= 10 {
			s = "10"
		} else {
			s = strconv.FormatFloat(v, 'f', 1, 64)
		}
	} else {
		v = math.Round(v)
		if v >= 1024 && u < len(units)-1 {
			u++
			s = "1.0"
		} else {
			s = strconv.FormatFloat(v, 'f', 0, 64)
		}
	}
	if lang == i18n.French {
		s = strings.Replace(s, ".", ",", 1)
	}
	return s + nbsp + units[u]
}

// FormatDateTime formats t, in UTC, as a date and a time of day the way lang
// writes them: "21 octobre 2026 à 14:30 UTC" in French, "October 21, 2026
// at 14:30 UTC" in English (and for any unsupported language).
func FormatDateTime(lang string, t time.Time) string {
	t = t.UTC()
	at := " at "
	if lang == i18n.French {
		at = " à "
	}
	return i18n.FormatDate(lang, t) + at + t.Format("15:04") + " UTC"
}
