package extension

// Config holds configuration for the Warden Forge extension.
type Config struct {
	// DisableRoutes disables the registration of HTTP routes.
	DisableRoutes bool `default:"false" json:"disable_routes"`

	// DisableMigrate disables auto-migration on start.
	DisableMigrate bool `default:"false" json:"disable_migrate"`
}
