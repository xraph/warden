// Package telemetry holds the small amount of tracing plumbing warden's
// packages share: the instrumentation scope, span start, and error marking
// that never copies an error message onto a span.
package telemetry

import (
	"context"
	"errors"
	"fmt"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"

	"github.com/xraph/warden/wardenerr"
)

// InstrumentationName is the instrumentation scope every warden span
// carries: the module path.
const InstrumentationName = "github.com/xraph/warden"

// StartSpan starts a span on the global tracer provider under warden's
// scope. The tracer is looked up on every call, the way forge and grove do
// it, so a provider installed after warden was loaded is the one used.
func StartSpan(ctx context.Context, name string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return otel.Tracer(InstrumentationName).Start(ctx, name, opts...)
}

// MarkError sets the span's status to Error and adds an exception event.
// Both carry only the error's type (ErrorType), never its message: store
// and driver messages quote values, and those can be personal data.
func MarkError(span trace.Span, err error) {
	if err == nil || !span.IsRecording() {
		return
	}
	typ := ErrorType(err)
	span.SetStatus(codes.Error, typ)
	span.AddEvent("exception", trace.WithAttributes(attribute.String("exception.type", typ)))
}

// sentinels are the errors ErrorType names directly, because their Go type
// (*errors.errorString) says nothing.
var sentinels = []struct {
	err  error
	name string
}{
	{context.Canceled, "context.Canceled"},
	{context.DeadlineExceeded, "context.DeadlineExceeded"},
	{wardenerr.ErrTenantRequired, "warden.ErrTenantRequired"},
	{wardenerr.ErrNotFound, "warden.ErrNotFound"},
	{wardenerr.ErrAlreadyExists, "warden.ErrAlreadyExists"},
	{wardenerr.ErrStaleWrite, "warden.ErrStaleWrite"},
}

// ErrorType names err's class for a span: a known sentinel's name, else
// the Go type of the innermost error in its Unwrap chain.
func ErrorType(err error) string {
	for _, s := range sentinels {
		if errors.Is(err, s.err) {
			return s.name
		}
	}
	for {
		next := errors.Unwrap(err)
		if next == nil {
			return fmt.Sprintf("%T", err)
		}
		err = next
	}
}
