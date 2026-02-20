package warden

import "context"

type contextKey int

const (
	ctxKeyAppID contextKey = iota
	ctxKeyTenantID
)

// WithTenant returns a context with the given app and tenant IDs.
// Use this for standalone mode (without Forge).
func WithTenant(ctx context.Context, appID, tenantID string) context.Context {
	ctx = context.WithValue(ctx, ctxKeyAppID, appID)
	ctx = context.WithValue(ctx, ctxKeyTenantID, tenantID)
	return ctx
}

func appIDFromContext(ctx context.Context) string {
	v, ok := ctx.Value(ctxKeyAppID).(string)
	if !ok {
		return ""
	}
	return v
}

func tenantIDFromContext(ctx context.Context) string {
	v, ok := ctx.Value(ctxKeyTenantID).(string)
	if !ok {
		return ""
	}
	return v
}
