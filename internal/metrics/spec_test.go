package metrics

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/ed-fr/transteira/api"
)

// TestSpecMetricNamesMatchCatalog checks that the list of metric names in
// the description of getMetrics (api/openapi.yaml) is the catalog.
func TestSpecMetricNamesMatchCatalog(t *testing.T) {
	t.Parallel()
	spec := string(api.OpenAPISpec)
	const start, end = "Metric names (all prefixed `transteira_`):", "New names may be added"
	i := strings.Index(spec, start)
	j := strings.Index(spec, end)
	if i < 0 || j < i {
		t.Fatal("the metric list of getMetrics is missing")
	}
	var got []string
	for _, m := range regexp.MustCompile("`([a-z0-9_]+)`").FindAllStringSubmatch(spec[i+len(start):j], -1) {
		got = append(got, "transteira_"+m[1])
	}
	var want []string
	for _, d := range Catalog() {
		want = append(want, d.Name)
	}
	slices.Sort(got)
	slices.Sort(want)
	if !slices.Equal(got, want) {
		t.Errorf("spec names = %v\ncatalog = %v", got, want)
	}
}
