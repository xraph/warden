package contract

import (
	"context"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/store/memory"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

func TestMaintenanceRunReportsZeroWhenNothingExpired(t *testing.T) {
	// A run that purged nothing succeeded. The page must be able to tell
	// that apart from a failure and from a run that removed rows, and the
	// only thing carrying that is these two counters.
	eng := testEngine(t, warden.Config{})
	h := maintenanceRunHandler(Deps{Engine: eng})

	got, err := h(context.Background(), struct{}{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("maintenance.run: %v", err)
	}
	if got.AssignmentsPurged != 0 || got.CheckLogsPurged != 0 {
		t.Errorf("result = %+v, want both zero", got)
	}
}

func TestMaintenanceRunPurgesExpiredAssignments(t *testing.T) {
	s := memory.New()
	seedAllow(t, s)
	past := time.Now().Add(-time.Hour)
	expired := &assignment.Assignment{
		TenantID:    "t1",
		SubjectKind: "user",
		SubjectID:   "bob",
		ExpiresAt:   &past,
	}
	if err := s.CreateAssignment(context.Background(), expired); err != nil {
		t.Fatalf("create expired assignment: %v", err)
	}
	eng, err := warden.NewEngine(warden.WithStore(s))
	if err != nil {
		t.Fatalf("new engine: %v", err)
	}

	h := maintenanceRunHandler(Deps{Engine: eng})
	got, err := h(context.Background(), struct{}{}, principalFor("t1"))
	if err != nil {
		t.Fatalf("maintenance.run: %v", err)
	}
	if got.AssignmentsPurged != 1 {
		t.Errorf("assignmentsPurged = %d, want 1", got.AssignmentsPurged)
	}
}

func TestCacheInvalidateWithoutASubjectClearsTheTenant(t *testing.T) {
	eng := testEngine(t, warden.Config{CacheTTL: time.Minute})
	h := cacheInvalidateHandler(Deps{Engine: eng})

	// Both forms must be accepted: a whole-tenant flush, and one subject.
	if _, err := h(context.Background(), CacheInvalidateInput{}, principalFor("t1")); err != nil {
		t.Fatalf("tenant invalidate: %v", err)
	}
	in := CacheInvalidateInput{SubjectKind: "user", SubjectID: "alice"}
	if _, err := h(context.Background(), in, principalFor("t1")); err != nil {
		t.Fatalf("subject invalidate: %v", err)
	}
}

func TestCacheInvalidateRejectsAHalfSpecifiedSubject(t *testing.T) {
	// A kind with no id, or an id with no kind, is a caller bug. Silently
	// flushing the whole tenant instead would be a much larger action than
	// the one that was asked for.
	eng := testEngine(t, warden.Config{CacheTTL: time.Minute})
	h := cacheInvalidateHandler(Deps{Engine: eng})

	_, err := h(context.Background(), CacheInvalidateInput{SubjectKind: "user"}, principalFor("t1"))
	if err == nil {
		t.Fatal("want an error for a subject kind with no id")
	}
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Errorf("want CodeBadRequest, got %v", err)
	}
}
