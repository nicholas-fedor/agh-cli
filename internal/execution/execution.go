// Copyright (c) 2026 - Nicholas Fedor <nick@nickfedor.com>
// SPDX-License-Identifier: AGPL-3.0-or-later

package execution

import (
	"context"
	"fmt"
	"strings"
)

// Target pairs a stable execution identity with an operation-specific value.
type Target[T any] struct {
	// Name identifies the target in reports and wrapped operation errors.
	Name string
	// Value is passed unchanged to the operation for this target.
	Value T
}

// Operation executes one unit of work for a [Target].
type Operation[T any] interface {
	// Execute performs the operation for target.
	//
	// Implementations should honor cancellation signaled through ctx.
	//
	// Parameters:
	//   - ctx: context governing the operation.
	//   - target: named value to process.
	//
	// Returns:
	//   - error: nil when the operation succeeds, or its failure otherwise.
	Execute(ctx context.Context, target Target[T]) error
}

// operationFunc adapts a function to [Operation].
type operationFunc[T any] func(ctx context.Context, target Target[T]) error

// Outcome records the result of one target's execution or preflight check.
type Outcome[T any] struct {
	// Target is the target associated with this outcome.
	Target Target[T]
	// Err is the operation or preflight error. Nil indicates success.
	Err error
	// Attempted reports whether Execute was called for Target.
	Attempted bool
}

// Report contains outcomes in target execution order.
type Report[T any] []Outcome[T]

// AggregateError contains failed target outcomes in execution order and exposes
// their errors through multi-error matching and unwrapping.
type AggregateError[T any] []Outcome[T]

// AdaptOperation adapts a function to an [Operation].
//
// Parameters:
//   - operation: function invoked for each target.
//
// Returns:
//   - Operation: an operation backed by operation.
func AdaptOperation[T any](
	operation func(ctx context.Context, target Target[T]) error,
) Operation[T] {
	return operationFunc[T](operation)
}

// Execute invokes the adapted function and adds target context to its error.
//
// Parameters:
//   - ctx: context passed to the adapted function.
//   - target: target passed to the adapted function.
//
// Returns:
//   - error: nil when the function succeeds, or a target-wrapped error.
func (f operationFunc[T]) Execute(ctx context.Context, target Target[T]) error {
	err := f(ctx, target)
	if err != nil {
		return fmt.Errorf("execute target %q: %w", target.Name, err)
	}

	return nil
}

// Err reports whether any recorded target failed.
//
// Returns:
//   - error: nil when every outcome succeeds, or an AggregateError containing
//     failed outcomes in execution order.
func (r Report[T]) Err() error {
	failures := r.failures()
	if len(failures) == 0 {
		return nil
	}

	return AggregateError[T](failures)
}

// Error formats every failed target in execution order.
//
// Returns:
//   - string: a failure count followed by each target name and error.
func (err AggregateError[T]) Error() string {
	var message strings.Builder

	_, writeErr := fmt.Fprintf(&message, "%d targets failed:", len(err))
	if writeErr != nil {
		return ""
	}

	for _, outcome := range err {
		_, writeErr = fmt.Fprintf(
			&message,
			"\n  %s: %v",
			outcome.Target.Name,
			outcome.Err,
		)
		if writeErr != nil {
			return message.String()
		}
	}

	return message.String()
}

// Unwrap exposes every target failure for error matching and extraction.
//
// Returns:
//   - []error: target errors in execution order.
func (err AggregateError[T]) Unwrap() []error {
	unwrapped := make([]error, 0, len(err))
	for _, outcome := range err {
		unwrapped = append(unwrapped, outcome.Err)
	}

	return unwrapped
}

// Run invokes operation sequentially in target order.
//
// An operation failure is recorded and execution continues with the next
// target. If ctx is canceled before a target begins, Run records one unattempted
// cancellation outcome for that target and omits all later targets.
//
// Parameters:
//   - ctx: context governing the complete run.
//   - targets: targets to process in order.
//   - operation: operation invoked for each attempted target.
//
// Returns:
//   - Report: outcomes in target execution order.
func Run[T any](
	ctx context.Context,
	targets []Target[T],
	operation Operation[T],
) Report[T] {
	report := make(Report[T], 0, len(targets))

	for _, target := range targets {
		err := ctx.Err()
		if err != nil {
			report = append(report, Outcome[T]{
				Target:    target,
				Err:       fmt.Errorf("run target: %w", err),
				Attempted: false,
			})

			break
		}

		err = operation.Execute(ctx, target)
		report = append(report, Outcome[T]{
			Target:    target,
			Err:       err,
			Attempted: true,
		})
	}

	return report
}

// failures returns failed outcomes in execution order.
//
// Parameters:
//   - r: outcomes to filter.
//
// Returns:
//   - []Outcome: a new slice containing outcomes whose Err is nonnil.
func (r Report[T]) failures() []Outcome[T] {
	failures := make([]Outcome[T], 0, len(r))
	for _, outcome := range r {
		if outcome.Err != nil {
			failures = append(failures, outcome)
		}
	}

	return failures
}
