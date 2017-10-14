package lastpass

// ConfigFunc allows modification of configurations
// in the Vault struct
type ConfigFunc func(opts *ConfigOptions)

// ConfigOptions are config options that
// set behaviours in Vault.
// Current supported configs is multi-factor auth.
type ConfigOptions struct {
	multiFactor string
}

// WithMultiFactor adds multi-factor auth to your vault.
func WithMultiFactor(code string) ConfigFunc {
	return func(opts *ConfigOptions) {
		opts.multiFactor = code
	}
}
