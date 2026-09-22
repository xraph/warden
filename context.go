package warden

import "context"

type contextKey int

const (
	ctxKeyAppID contextKey = iota
	ctxKeyTenantID
	ctxKeyNamespacePath
	ctxKeyRequestIP
)

// WithTenant returns a context with the given app and tenant IDs.
// Use this for standalone mode (without Forge).
func WithTenant(ctx context.Context, appID, tenantID string) context.Context {
	ctx = context.WithValue(ctx, ctxKeyAppID, appID)
	ctx = context.WithValue(ctx, ctxKeyTenantID, tenantID)
	return ctx
}

// WithNamespace returns a context with the given namespace path overlaid on
// top of the existing tenant scope. Pass empty string for the tenant root.
//
// Combine with WithTenant when needed:
//
//	ctx := warden.WithTenant(context.Background(), "app1", "t1")
//	ctx  = warden.WithNamespace(ctx, "engineering/platform")
func WithNamespace(ctx context.Context, namespacePath string) context.Context {
	return context.WithValue(ctx, ctxKeyNamespacePath, namespacePath)
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

func namespacePathFromContext(ctx context.Context) string {
	v, ok := ctx.Value(ctxKeyNamespacePath).(string)
	if !ok {
		return ""
	}
	return v
}

// WithRequestIP returns a context carrying the caller's IP address, used to
// populate CheckLog entries (checklog.Entry.RequestIP). Typically set once
// per inbound request by the HTTP/gRPC middleware layer.
func WithRequestIP(ctx context.Context, ip string) context.Context {
	return context.WithValue(ctx, ctxKeyRequestIP, ip)
}

func requestIPFromContext(ctx context.Context) string {
	v, ok := ctx.Value(ctxKeyRequestIP).(string)
	if !ok {
		return ""
	}
	return v
}
