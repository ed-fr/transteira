package config

import "strings"

// Problem describes one invalid configuration variable.
type Problem struct {
	// Variable is the name of the offending environment variable.
	Variable string
	// Reason explains what is wrong. It never contains a secret value.
	Reason string
	// Err is the underlying error, when there is one, so that callers can
	// match sentinels such as [ErrTrustedProxiesTooBroad] with [errors.Is].
	Err error
}

// String formats the problem as "VARIABLE: reason".
func (p Problem) String() string {
	return p.Variable + ": " + p.Reason
}

// ValidationError lists every configuration problem found by [Load], so that
// an operator can fix them all at once instead of one restart per mistake.
type ValidationError struct {
	// Problems holds the problems in the order they were detected.
	Problems []Problem
}

// Error implements the error interface.
func (e *ValidationError) Error() string {
	var b strings.Builder
	b.WriteString("invalid configuration:")
	for _, p := range e.Problems {
		b.WriteString("\n  - ")
		b.WriteString(p.String())
	}
	return b.String()
}

// Unwrap returns the underlying errors of the problems, for [errors.Is] and
// [errors.As].
func (e *ValidationError) Unwrap() []error {
	var errs []error
	for _, p := range e.Problems {
		if p.Err != nil {
			errs = append(errs, p.Err)
		}
	}
	return errs
}

// Has reports whether a problem was recorded for the given variable.
func (e *ValidationError) Has(variable string) bool {
	for _, p := range e.Problems {
		if p.Variable == variable {
			return true
		}
	}
	return false
}
