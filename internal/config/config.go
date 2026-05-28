package config

// Config holds CLI configuration values.
type Config struct {
	Path       string   `json:"path"`
	Format     string   `json:"format"`
	Ecosystems []string `json:"ecosystems"`
	FailOn     string   `json:"fail_on"`
	PolicyPath string   `json:"policy_path"`
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Path:       ".",
		Format:     "text",
		Ecosystems: nil,
		FailOn:     "NONE",
		PolicyPath: ".chainsaw.yaml",
	}
}
