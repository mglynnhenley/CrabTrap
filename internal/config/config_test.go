package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestExpandEnvVars(t *testing.T) {
	os.Setenv("TEST_DB_URL", "postgres://localhost/test")
	defer os.Unsetenv("TEST_DB_URL")

	config := &Config{
		Database: DatabaseConfig{
			URL: "${TEST_DB_URL}",
		},
		TLS: TLSConfig{
			CACertPath: "./certs/${TEST_DB_URL}/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
	}

	config.expandEnvVars()

	if config.Database.URL != "postgres://localhost/test" {
		t.Errorf("Expected database URL to be expanded, got '%s'", config.Database.URL)
	}

	// Non-secret fields should remain unchanged
	if config.TLS.CACertPath != "./certs/${TEST_DB_URL}/ca.crt" {
		t.Errorf("Expected ca_cert_path to remain unchanged, got '%s'", config.TLS.CACertPath)
	}
}

func TestLoadWithEnvVars(t *testing.T) {
	os.Setenv("TEST_DB_URL", "postgres://localhost/test")
	defer os.Unsetenv("TEST_DB_URL")

	configContent := `
proxy:
  port: 8080

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough
  timeout: 30s

audit:
  output: stdout
  format: json

database:
  url: "${TEST_DB_URL}"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	config, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if config.Database.URL != "postgres://localhost/test" {
		t.Errorf("Expected database URL to be expanded, got '%s'", config.Database.URL)
	}
}

func TestValidateLLMModeRequiresJudgeEnabled(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "llm"},
		LLMJudge: LLMJudgeConfig{Enabled: false},
	}

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error when approval.mode=llm but llm_judge.enabled=false")
	}
}

func TestValidateLLMModeWithJudgeEnabled(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "llm"},
		LLMJudge: LLMJudgeConfig{Enabled: true},
	}

	if err := config.validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}
}

func TestValidatePassthroughMode(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}

	if err := config.validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}
}

func TestValidateApprovalModeRejectsUnknownValue(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "invalid"},
	}

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for unknown approval.mode")
	}
}

func TestValidateFallbackModeRejectsManual(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
		LLMJudge: LLMJudgeConfig{FallbackMode: "manual"},
	}

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for fallback_mode=manual (no longer supported)")
	}
}

func TestDefaultConfigIsValid(t *testing.T) {
	config := Default()
	if err := config.validate(); err != nil {
		t.Fatalf("Default() should produce a valid config, but validate() returned: %v", err)
	}
}

func TestValidateApprovalModeRejectsManual(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "manual"},
	}

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for manual approval.mode (no longer supported)")
	}
}

func TestAllowedPrivateCIDRs_LoadFromYAML(t *testing.T) {
	configContent := `
proxy:
  port: 8080
  allowed_private_cidrs:
    - "10.0.0.0/8"
    - "172.16.5.0/24"

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.Proxy.AllowedPrivateCIDRs) != 2 {
		t.Fatalf("Expected 2 allowed CIDRs, got %d", len(cfg.Proxy.AllowedPrivateCIDRs))
	}
	if cfg.Proxy.AllowedPrivateCIDRs[0] != "10.0.0.0/8" {
		t.Errorf("Expected first CIDR to be 10.0.0.0/8, got %q", cfg.Proxy.AllowedPrivateCIDRs[0])
	}
	if cfg.Proxy.AllowedPrivateCIDRs[1] != "172.16.5.0/24" {
		t.Errorf("Expected second CIDR to be 172.16.5.0/24, got %q", cfg.Proxy.AllowedPrivateCIDRs[1])
	}
}

func TestAllowedPrivateCIDRs_InvalidCIDRRejected(t *testing.T) {
	configContent := `
proxy:
  port: 8080
  allowed_private_cidrs:
    - "not-a-cidr"

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	_, err := Load(configPath)
	if err == nil {
		t.Fatal("Expected validation error for invalid CIDR, got nil")
	}
}

func TestAllowedPrivateCIDRs_EmptyByDefault(t *testing.T) {
	cfg := Default()
	if len(cfg.Proxy.AllowedPrivateCIDRs) != 0 {
		t.Errorf("Expected no allowed CIDRs by default, got %v", cfg.Proxy.AllowedPrivateCIDRs)
	}
}

func TestInsecureSkipVerifyHosts_LoadFromYAML(t *testing.T) {
	configContent := `
proxy:
  port: 8080
  insecure_skip_verify_hosts:
    - "internal.example.com"
    - "dev.local"

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if len(cfg.Proxy.InsecureSkipVerifyHosts) != 2 {
		t.Fatalf("Expected 2 hosts, got %d", len(cfg.Proxy.InsecureSkipVerifyHosts))
	}
	if cfg.Proxy.InsecureSkipVerifyHosts[0] != "internal.example.com" {
		t.Errorf("Expected first host to be internal.example.com, got %q", cfg.Proxy.InsecureSkipVerifyHosts[0])
	}
	if cfg.Proxy.InsecureSkipVerifyHosts[1] != "dev.local" {
		t.Errorf("Expected second host to be dev.local, got %q", cfg.Proxy.InsecureSkipVerifyHosts[1])
	}
}

func TestInsecureSkipVerifyHosts_EmptyEntryRejected(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{
			Port:                    8080,
			InsecureSkipVerifyHosts: []string{"valid.example.com", ""},
		},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for empty host entry, got nil")
	}
}

func TestInsecureSkipVerifyHosts_PortEntryAccepted(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{
			Port:                    8080,
			InsecureSkipVerifyHosts: []string{"internal.example.com:9001", "dev.local"},
		},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}

	if err := config.validate(); err != nil {
		t.Fatalf("Expected host:port entry to be accepted, got: %v", err)
	}
}

func TestInsecureSkipVerifyHosts_EmptyByDefault(t *testing.T) {
	cfg := Default()
	if len(cfg.Proxy.InsecureSkipVerifyHosts) != 0 {
		t.Errorf("Expected no skip verify hosts by default, got %v", cfg.Proxy.InsecureSkipVerifyHosts)
	}
}

func intPtr(i int) *int { return &i }

func TestRateLimitPerIP_EnabledByDefault(t *testing.T) {
	cfg := Default()
	if cfg.Proxy.RateLimitPerIP == nil || *cfg.Proxy.RateLimitPerIP != 50 {
		t.Errorf("Expected rate_limit_per_ip to default to 50, got %v", cfg.Proxy.RateLimitPerIP)
	}
	if cfg.Proxy.RateLimitBurst != 100 {
		t.Errorf("Expected rate_limit_burst to default to 100, got %d", cfg.Proxy.RateLimitBurst)
	}
}

func TestRateLimitPerIP_ExplicitZeroDisables(t *testing.T) {
	configContent := `
proxy:
  port: 8080
  rate_limit_per_ip: 0

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Proxy.RateLimitPerIP == nil || *cfg.Proxy.RateLimitPerIP != 0 {
		t.Errorf("Expected rate_limit_per_ip to be 0 (explicitly disabled), got %v", cfg.Proxy.RateLimitPerIP)
	}
}

func TestRateLimitPerIP_NegativeRejected(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080, RateLimitPerIP: intPtr(-1)},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}
	config.applyDefaults()

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for negative rate_limit_per_ip")
	}
}

func TestRateLimitBurst_NegativeRejected(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080, RateLimitBurst: -1},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}
	config.applyDefaults()

	if err := config.validate(); err == nil {
		t.Fatal("Expected validation error for negative rate_limit_burst")
	}
}

func TestRateLimitPerIP_BurstDefaultApplied(t *testing.T) {
	config := Default()
	rate := 50
	config.Proxy.RateLimitPerIP = &rate
	config.Proxy.RateLimitBurst = 0
	config.applyDefaults()

	if config.Proxy.RateLimitBurst != 100 {
		t.Errorf("Expected burst to default to 100 when rate_limit_per_ip is set, got %d", config.Proxy.RateLimitBurst)
	}
}

func TestRateLimitPerIP_PositiveAccepted(t *testing.T) {
	config := &Config{
		Proxy: ProxyConfig{Port: 8080, RateLimitPerIP: intPtr(50), RateLimitBurst: 100},
		TLS: TLSConfig{
			CACertPath: "./certs/ca.crt",
			CAKeyPath:  "./certs/ca.key",
		},
		Audit:    AuditConfig{Format: "json"},
		Approval: ApprovalConfig{Mode: "passthrough"},
	}
	config.applyDefaults()

	if err := config.validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}
}

func TestProbesConfig_DisabledByDefault(t *testing.T) {
	cfg := Default()
	if cfg.Probes.Enabled {
		t.Errorf("Expected probes disabled by default, got enabled")
	}
}

func TestProbesConfig_DefaultsApplied(t *testing.T) {
	cfg := Default()
	if cfg.Probes.Timeout != 2*time.Second {
		t.Errorf("Expected probes.timeout default 2s, got %s", cfg.Probes.Timeout)
	}
	if cfg.Probes.BatchSize != 8 {
		t.Errorf("Expected probes.batch_size default 8, got %d", cfg.Probes.BatchSize)
	}
	if cfg.Probes.MaxBodyBytes != 32*1024 {
		t.Errorf("Expected probes.max_body_bytes default 32768, got %d", cfg.Probes.MaxBodyBytes)
	}
	if cfg.Probes.MaxConcurrency != 100 {
		t.Errorf("Expected probes.max_concurrency default 100, got %d", cfg.Probes.MaxConcurrency)
	}
	if cfg.Probes.CircuitBreakerThreshold != 5 {
		t.Errorf("Expected probes.circuit_breaker_threshold default 5, got %d", cfg.Probes.CircuitBreakerThreshold)
	}
	if cfg.Probes.CircuitBreakerCooldown != 10*time.Second {
		t.Errorf("Expected probes.circuit_breaker_cooldown default 10s, got %s", cfg.Probes.CircuitBreakerCooldown)
	}
}

func TestProbesConfig_EnabledRequiresEndpoint(t *testing.T) {
	cfg := Default()
	cfg.Probes.Enabled = true
	if err := cfg.validate(); err == nil {
		t.Fatal("Expected validation error when probes.enabled and endpoint missing")
	}
}

// The Modal hallucination probe service does not require an API key. APIKey is
// optional; only Endpoint is required when probes are enabled.
func TestProbesConfig_EnabledValidWithoutAPIKey(t *testing.T) {
	cfg := Default()
	cfg.Probes.Enabled = true
	cfg.Probes.Endpoint = "https://probes.example"
	if err := cfg.validate(); err != nil {
		t.Fatalf("Unexpected validation error: %v", err)
	}
}

func TestProbesConfig_LoadFromYAMLAndEnvExpand(t *testing.T) {
	os.Setenv("TEST_PROBE_URL", "https://probes.test")
	os.Setenv("TEST_PROBE_KEY", "secret-key")
	defer os.Unsetenv("TEST_PROBE_URL")
	defer os.Unsetenv("TEST_PROBE_KEY")

	configContent := `
proxy:
  port: 8080

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"

probes:
  enabled: true
  endpoint: "${TEST_PROBE_URL}"
  api_key: "${TEST_PROBE_KEY}"
  batch_size: 16
  timeout: 1s
  max_body_bytes: 4096
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if !cfg.Probes.Enabled {
		t.Error("Expected probes enabled")
	}
	if cfg.Probes.Endpoint != "https://probes.test" {
		t.Errorf("Expected probes.endpoint expanded, got %q", cfg.Probes.Endpoint)
	}
	if cfg.Probes.APIKey != "secret-key" {
		t.Errorf("Expected probes.api_key expanded, got %q", cfg.Probes.APIKey)
	}
	if cfg.Probes.BatchSize != 16 {
		t.Errorf("Expected probes.batch_size 16, got %d", cfg.Probes.BatchSize)
	}
	if cfg.Probes.Timeout != time.Second {
		t.Errorf("Expected probes.timeout 1s, got %s", cfg.Probes.Timeout)
	}
	if cfg.Probes.MaxBodyBytes != 4096 {
		t.Errorf("Expected probes.max_body_bytes 4096, got %d", cfg.Probes.MaxBodyBytes)
	}
}

func TestRateLimitPerIP_LoadFromYAML(t *testing.T) {
	configContent := `
proxy:
  port: 8080
  rate_limit_per_ip: 75
  rate_limit_burst: 200

tls:
  ca_cert_path: ./certs/ca.crt
  ca_key_path: ./certs/ca.key

approval:
  mode: passthrough

audit:
  output: stdout
  format: json

database:
  url: "postgres://localhost/test"
`

	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "test-config.yaml")
	if err := os.WriteFile(configPath, []byte(configContent), 0644); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	if cfg.Proxy.RateLimitPerIP == nil || *cfg.Proxy.RateLimitPerIP != 75 {
		t.Errorf("Expected rate_limit_per_ip 75, got %v", cfg.Proxy.RateLimitPerIP)
	}
	if cfg.Proxy.RateLimitBurst != 200 {
		t.Errorf("Expected rate_limit_burst 200, got %d", cfg.Proxy.RateLimitBurst)
	}
}
