// Package auditlog provides an in-tree structured-log Audit plugin.
//
// It implements plugin.Audit and writes one structured log line per audit
// event through a go-utils/log.Logger (which forge.Logger re-exports, so
// any Forge extension logger satisfies it directly). The extension
// registers it by default; disable with the extension config key
// auth.audit_log: false.
package auditlog

import (
	"context"

	log "github.com/xraph/go-utils/log"

	"github.com/xraph/warden"
	"github.com/xraph/warden/plugin"
)

// Logger is the plugin's logging dependency. go-utils/log.Logger (and
// therefore forge.Logger, a re-export of the same interface) satisfies
// it directly.
type Logger = log.Logger

// Plugin is a plugin.Audit sink that logs one structured Info line per
// audit event.
type Plugin struct {
	logger Logger
}

var (
	_ plugin.Plugin = (*Plugin)(nil)
	_ plugin.Audit  = (*Plugin)(nil)
)

// New creates an audit-log plugin writing through logger. A nil logger
// falls back to a no-op logger rather than panicking, so a caller that
// forgets to wire one gets silence instead of a crash.
func New(logger Logger) *Plugin {
	if logger == nil {
		logger = log.NewNoopLogger()
	}
	return &Plugin{logger: logger}
}

// Name implements plugin.Plugin.
func (p *Plugin) Name() string { return "auditlog" }

// OnAudit implements plugin.Audit. It never returns an error: a
// logging failure must not affect the mutation that triggered it, and
// the registry already recovers panics from plugin hooks.
func (p *Plugin) OnAudit(_ context.Context, ev plugin.Event) error {
	fields := []log.Field{
		log.String("action", ev.Action),
		log.String("tenant_id", ev.TenantID),
		log.String("entity_id", ev.EntityID),
		log.Time("at", ev.At),
	}
	if ev.RequestID != "" {
		fields = append(fields, log.String("request_id", ev.RequestID))
	}
	if ev.TraceID != "" {
		fields = append(fields, log.String("trace_id", ev.TraceID))
	}
	if a, ok := ev.Actor.(warden.Actor); ok {
		fields = append(fields,
			log.String("actor_kind", a.Kind),
			log.String("actor_id", a.ID),
			log.String("actor_via", a.Via),
		)
	} else if ev.Actor != nil {
		fields = append(fields, log.Any("actor", ev.Actor))
	}
	if ev.Entity != nil {
		fields = append(fields, log.Any("entity", ev.Entity))
	}
	if ev.Before != nil {
		fields = append(fields, log.Any("before", ev.Before))
	}
	p.logger.Info("warden: audit", fields...)
	return nil
}
