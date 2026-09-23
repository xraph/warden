package warden

// callOptions holds per-call overrides resolved from CallOption values.
type callOptions struct {
	tenantID         string
	appID            string
	namespacePath    string
	namespacePathSet bool // distinguishes "explicitly set to empty" from "not set"
	dryRun           bool
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

// WithCallNamespacePath overrides the namespace path for this single call.
// Pass empty string to scope the call to the tenant root.
func WithCallNamespacePath(namespacePath string) CallOption {
	return func(o *callOptions) {
		o.namespacePath = namespacePath
		o.namespacePathSet = true
	}
}

// WithCallDryRun evaluates the check without any of its side effects: the
// result cache is neither read nor written, no check log entry is enqueued,
// and no plugin hooks fire.
//
// It exists for callers that ask "what would this decide" rather than
// "decide this", the dashboard playground above all. Without it, pressing
// a playground button writes an audit entry indistinguishable from
// production traffic, fires PolicyObligationFired at whatever is listening,
// and serves the second press from cache, which skips evaluation entirely
// and reports a cache lookup as the evaluation time.
//
// The decision itself is identical. Only the side effects are suppressed.
func WithCallDryRun() CallOption {
	return func(o *callOptions) {
		o.dryRun = true
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
