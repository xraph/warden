package extension

import (
	"testing"
	"time"
)

func TestConfig_Validate_DefaultsAreValid(t *testing.T) {
	if err := DefaultConfig().Validate(); err != nil {
		t.Fatalf("DefaultConfig().Validate() = %v, want nil", err)
	}
}

func TestConfig_Validate_RejectsNegativeMaxGraphDepth(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxGraphDepth = -1
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for a negative MaxGraphDepth")
	}
}

func TestConfig_Validate_RejectsMaxGraphDepthOver64(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxGraphDepth = 65
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for MaxGraphDepth > 64")
	}
}

func TestConfig_Validate_DelegatesEngineKnobsToWardenConfig(t *testing.T) {
	// CacheTTL > 24h is rejected by warden.Config.Validate; Config.Validate
	// must surface that through toEngineConfig rather than silently
	// accepting an engine-level-invalid value.
	cfg := DefaultConfig()
	cfg.CacheTTL = 48 * time.Hour
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for a CacheTTL over 24h (delegated to warden.Config.Validate)")
	}
}

func TestConfig_Validate_RejectsNegativeMaxBatchChecks(t *testing.T) {
	cfg := DefaultConfig()
	cfg.MaxBatchChecks = -5
	if err := cfg.Validate(); err == nil {
		t.Fatal("expected an error for a negative MaxBatchChecks")
	}
}

func TestDefaultAuthConfig_SecureByDefault(t *testing.T) {
	a := DefaultAuthConfig()
	if !a.RequireIdentity {
		t.Error("RequireIdentity should default to true")
	}
	if a.AllowAnonymousChecks {
		t.Error("AllowAnonymousChecks should default to false")
	}
	if !a.AuditLog {
		t.Error("AuditLog should default to true")
	}
}

func TestMergeWithDefaults_FillsAuthWhenUntouched(t *testing.T) {
	e := New()
	got := e.mergeWithDefaults(Config{})
	if !got.Auth.RequireIdentity || !got.Auth.AuditLog {
		t.Fatalf("Auth not defaulted when the whole struct was zero: %+v", got.Auth)
	}
}

func TestMergeWithDefaults_PreservesExplicitAuth(t *testing.T) {
	e := New()
	explicit := AuthConfig{RequireIdentity: false, AllowAnonymousChecks: true, AuditLog: false}
	got := e.mergeWithDefaults(Config{Auth: explicit})
	if got.Auth != explicit {
		t.Fatalf("mergeWithDefaults overwrote an explicitly-set Auth: got %+v, want %+v", got.Auth, explicit)
	}
}

func TestMergeWithDefaults_FillsEngineKnobsWhenZero(t *testing.T) {
	e := New()
	got := e.mergeWithDefaults(Config{})
	d := DefaultConfig()
	if got.CacheMaxSize != d.CacheMaxSize {
		t.Errorf("CacheMaxSize = %d, want default %d", got.CacheMaxSize, d.CacheMaxSize)
	}
	if got.MaxGraphVisited != d.MaxGraphVisited {
		t.Errorf("MaxGraphVisited = %d, want default %d", got.MaxGraphVisited, d.MaxGraphVisited)
	}
	if got.MaxBatchChecks != d.MaxBatchChecks {
		t.Errorf("MaxBatchChecks = %d, want default %d", got.MaxBatchChecks, d.MaxBatchChecks)
	}
	if got.CheckLogRetention != d.CheckLogRetention {
		t.Errorf("CheckLogRetention = %v, want default %v", got.CheckLogRetention, d.CheckLogRetention)
	}
}

func TestToEngineConfig_MirrorsFields(t *testing.T) {
	cfg := Config{
		MaxGraphDepth:       7,
		CacheTTL:            time.Minute,
		CacheMaxSize:        123,
		MaxGraphVisited:     456,
		MaxGraphFanout:      789,
		EvaluateAllModels:   true,
		CheckLogQueueSize:   111,
		CheckLogRetention:   time.Hour,
		MaintenanceInterval: 2 * time.Hour,
		MaxBatchChecks:      42,
	}
	ec := cfg.toEngineConfig()
	if ec.MaxGraphDepth != 7 || ec.CacheTTL != time.Minute || ec.CacheMaxSize != 123 ||
		ec.MaxGraphVisited != 456 || ec.MaxGraphFanout != 789 || !ec.EvaluateAllModels ||
		ec.CheckLogQueueSize != 111 || ec.CheckLogRetention != time.Hour ||
		ec.MaintenanceInterval != 2*time.Hour || ec.MaxBatchChecks != 42 {
		t.Fatalf("toEngineConfig did not mirror every field: %+v", ec)
	}
}
