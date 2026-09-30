package warden

import (
	"context"
	"testing"

	"github.com/xraph/warden/store/memory"
)

func TestEngineCheckLogLossIsUnavailableWhenLoggingIsOff(t *testing.T) {
	off := false
	eng, err := NewEngine(WithStore(memory.New()), WithConfig(Config{EnableCheckLog: &off}))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	if _, ok := eng.CheckLogLoss(); ok {
		t.Fatal("want ok=false with check logging off")
	}
}

func TestEngineCheckLogLossStartsAtZeroWhenLoggingIsOn(t *testing.T) {
	eng, err := NewEngine(WithStore(memory.New()))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}
	defer func() { _ = eng.Stop(context.Background()) }()
	loss, ok := eng.CheckLogLoss()
	if !ok {
		t.Fatal("want ok=true with check logging on by default")
	}
	if loss.QueueFull != 0 || loss.WriteFailed != 0 || loss.Since.IsZero() {
		t.Fatalf("want zero loss with a start time, got %+v", loss)
	}
}
