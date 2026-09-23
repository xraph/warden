package contract

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

func testEngine(t *testing.T, cfg warden.Config) *warden.Engine {
	t.Helper()
	eng, err := warden.NewEngine(warden.WithStore(memory.New()), warden.WithConfig(cfg))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	return eng
}

func TestConfigDetailReportsTheEngineConfig(t *testing.T) {
	falseVal := false
	eng := testEngine(t, warden.Config{
		MaxGraphDepth:     7,
		CacheTTL:          30 * time.Second,
		EnableCheckLog:    &falseVal,
		CheckLogRetention: 48 * time.Hour,
	})

	h := configDetailHandler(Deps{Engine: eng})
	got, err := h(context.Background(), struct{}{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("config.detail: %v", err)
	}

	if got.MaxGraphDepth != 7 {
		t.Errorf("maxGraphDepth = %d, want 7", got.MaxGraphDepth)
	}
	// The banner on the config page keys off this exact field. An empty
	// check log is otherwise indistinguishable from an idle system.
	if got.CheckLogEnabled {
		t.Error("checkLogEnabled = true, want false")
	}
	if got.CacheTTLSeconds != 30 {
		t.Errorf("cacheTtlSeconds = %d, want 30", got.CacheTTLSeconds)
	}
	if got.CheckLogRetentionHours != 48 {
		t.Errorf("checkLogRetentionHours = %d, want 48", got.CheckLogRetentionHours)
	}
}

func TestConfigDetailDefaultsAreReportedAsEnabled(t *testing.T) {
	// Every Enable* flag is a *bool where nil means enabled. A handler that
	// dereferences it naively panics; one that treats nil as false reports
	// a correctly-configured engine as switched off.
	eng := testEngine(t, warden.Config{})

	h := configDetailHandler(Deps{Engine: eng})
	got, err := h(context.Background(), struct{}{}, dashcontract.Principal{})
	if err != nil {
		t.Fatalf("config.detail: %v", err)
	}

	if !got.RBACEnabled || !got.ABACEnabled || !got.ReBACEnabled || !got.CheckLogEnabled {
		t.Errorf("nil Enable* flags must report enabled, got %+v", got)
	}
}

func TestConfigDetailWithoutAnEngineIsUnavailable(t *testing.T) {
	h := configDetailHandler(Deps{})
	_, err := h(context.Background(), struct{}{}, dashcontract.Principal{})
	if err == nil {
		t.Fatal("want an error when no engine is configured")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeUnavailable {
		t.Errorf("want CodeUnavailable, got %v", err)
	}
}

func errorsAs(err error, target any) bool { return errors.As(err, target) }
