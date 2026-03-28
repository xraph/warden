package warden

// callOptions holds per-call overrides resolved from CallOption values.
type callOptions struct {
	tenantID string
	appID    string
}

// CallOption is a functional option applied per-call on Check, Enforce, and CanI.
// It is distinct from Option, which configures the Engine at construction time.
type CallOption func(*callOptions)

// WithCallTenantID overrides the tenant ID for this single call.
// It takes precedence over context-derived scope and CheckRequest.TenantID.
func WithCallTenantID(tenantID string) CallOption {
	return func(o *callOptions) {
		o.tenantID = tenantID
	}
}

// WithCallAppID overrides the app ID for this single call.
func WithCallAppID(appID string) CallOption {
	return func(o *callOptions) {
		o.appID = appID
	}
}

// resolveCallOptions folds variadic CallOption values into a callOptions struct.
func resolveCallOptions(opts []CallOption) callOptions {
	var co callOptions
	for _, opt := range opts {
		opt(&co)
	}
	return co
}
