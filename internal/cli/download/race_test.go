//go:build race

package download

// raceEnabled skips the memory test under the race detector, whose
// shadow memory and slowdown make the measure meaningless.
const raceEnabled = true
