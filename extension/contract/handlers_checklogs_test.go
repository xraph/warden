package contract

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/xraph/warden"
	"github.com/xraph/warden/checklog"
	"github.com/xraph/warden/id"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// checkLogT0 is the instant the seeded rows are anchored to. Every row's
// CreatedAt is set explicitly, so the after and before filters are tested
// against known instants rather than against a clock.
var checkLogT0 = time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)

// seedCheckLog writes one row straight into the engine's store. Never
// through Check: its writer is asynchronous, so a test that seeded that way
// would race the read it is about to make.
func seedCheckLog(t *testing.T, eng *warden.Engine, e *checklog.Entry) *checklog.Entry {
	t.Helper()
	if e.ID.IsNil() {
		e.ID = id.NewCheckLogID()
	}
	if err := eng.Store().CreateCheckLog(context.Background(), e); err != nil {
		t.Fatalf("seed check log: %v", err)
	}
	return e
}

// checkLogFixture seeds two rows in t1 that differ in every filterable
// field, plus a row in t2 that matches the first t1 row on everything but
// the tenant. So each filter has exactly one matching t1 row and one that
// does not match, and a filter that leaked across tenants would show.
type checkLogFixture struct {
	eng   *warden.Engine
	a, b  *checklog.Entry
	other *checklog.Entry
}

func newCheckLogFixture(t *testing.T) checkLogFixture {
	t.Helper()
	eng := testEngine(t, warden.Config{})
	f := checkLogFixture{eng: eng}
	f.a = seedCheckLog(t, eng, &checklog.Entry{
		TenantID: "t1", NamespacePath: "", SubjectKind: "user", SubjectID: "alice",
		Action: "read", ResourceType: "document", ResourceID: "d1",
		Decision: "allow", Cached: false, CreatedAt: checkLogT0,
	})
	f.b = seedCheckLog(t, eng, &checklog.Entry{
		TenantID: "t1", NamespacePath: "eng", SubjectKind: "service", SubjectID: "billing",
		Action: "write", ResourceType: "invoice", ResourceID: "i1",
		Decision: "deny_default", Cached: true, CreatedAt: checkLogT0.Add(time.Hour),
	})
	f.other = seedCheckLog(t, eng, &checklog.Entry{
		TenantID: "t2", NamespacePath: "", SubjectKind: "user", SubjectID: "alice",
		Action: "read", ResourceType: "document", ResourceID: "d1",
		Decision: "allow", Cached: false, CreatedAt: checkLogT0.Add(30 * time.Minute),
	})
	return f
}

func ptr[T any](v T) *T { return &v }

func listCheckLogs(t *testing.T, eng *warden.Engine, tenant string, in CheckLogsListInput) (CheckLogsListResponse, error) {
	t.Helper()
	return checkLogsListHandler(Deps{Engine: eng})(context.Background(), in, principalFor(tenant))
}

func idsOf(items []CheckLogSummary) []string {
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.ID)
	}
	return out
}

func TestCheckLogsListFiltersOneAtATime(t *testing.T) {
	f := newCheckLogFixture(t)
	both := []string{f.b.ID.String(), f.a.ID.String()} // newest first
	onlyA := []string{f.a.ID.String()}
	onlyB := []string{f.b.ID.String()}
	mid := checkLogT0.Add(30 * time.Minute).Format(time.RFC3339)

	cases := []struct {
		name string
		in   CheckLogsListInput
		want []string
	}{
		{"no filter", CheckLogsListInput{}, both},
		{"namespacePath nil is every namespace", CheckLogsListInput{NamespacePath: nil}, both},
		{"namespacePath empty is the root", CheckLogsListInput{NamespacePath: ptr("")}, onlyA},
		{"namespacePath eng", CheckLogsListInput{NamespacePath: ptr("eng")}, onlyB},
		{"subjectKind", CheckLogsListInput{SubjectKind: "service"}, onlyB},
		{"subjectId", CheckLogsListInput{SubjectID: "alice"}, onlyA},
		{"action", CheckLogsListInput{Action: "write"}, onlyB},
		{"resourceType", CheckLogsListInput{ResourceType: "document"}, onlyA},
		{"resourceId", CheckLogsListInput{ResourceID: "i1"}, onlyB},
		{"decision allow", CheckLogsListInput{Decision: "allow"}, onlyA},
		{"decision deny_default", CheckLogsListInput{Decision: "deny_default"}, onlyB},
		{"cached true", CheckLogsListInput{Cached: ptr(true)}, onlyB},
		{"cached false", CheckLogsListInput{Cached: ptr(false)}, onlyA},
		{"after", CheckLogsListInput{After: mid}, onlyB},
		{"before", CheckLogsListInput{Before: mid}, onlyA},
		// Both bounds are inclusive: a row created exactly at the bound is in.
		{"after is inclusive", CheckLogsListInput{After: checkLogT0.Add(time.Hour).Format(time.RFC3339)}, onlyB},
		{"before is inclusive", CheckLogsListInput{Before: checkLogT0.Format(time.RFC3339)}, onlyA},
		{"after equal to before is one instant", CheckLogsListInput{
			After: checkLogT0.Format(time.RFC3339), Before: checkLogT0.Format(time.RFC3339),
		}, onlyA},
		// Row b sits exactly at T0+1h. An After half a second later is a real
		// fractional instant, so it excludes b. Truncating it to whole seconds
		// would put it back at T0+1h and wrongly include b.
		{"fractional seconds parse", CheckLogsListInput{After: checkLogT0.Add(time.Hour + 500*time.Millisecond).Format(time.RFC3339Nano)}, []string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := listCheckLogs(t, f.eng, "t1", tc.in)
			if err != nil {
				t.Fatalf("checkLogs.list: %v", err)
			}
			if !reflect.DeepEqual(idsOf(got.Items), tc.want) {
				t.Errorf("ids = %v, want %v", idsOf(got.Items), tc.want)
			}
			if got.Total != int64(len(tc.want)) {
				t.Errorf("total = %d, want %d", got.Total, len(tc.want))
			}
		})
	}
}

func TestCheckLogsListDecisionErrorIsAKnownDecision(t *testing.T) {
	// "error" is what the engine writes when an evaluation fails, so a
	// filter on it must be accepted, not refused with the typos.
	eng := testEngine(t, warden.Config{})
	e := seedCheckLog(t, eng, &checklog.Entry{TenantID: "t1", Decision: "error", Error: "boom", CreatedAt: checkLogT0})
	seedCheckLog(t, eng, &checklog.Entry{TenantID: "t1", Decision: "allow", CreatedAt: checkLogT0})

	got, err := listCheckLogs(t, eng, "t1", CheckLogsListInput{Decision: "error"})
	if err != nil {
		t.Fatalf("checkLogs.list: %v", err)
	}
	if !reflect.DeepEqual(idsOf(got.Items), []string{e.ID.String()}) || got.Total != 1 {
		t.Errorf("got %v total %d, want only the error row", idsOf(got.Items), got.Total)
	}
	if got.Items[0].Error != "boom" {
		t.Errorf("error = %q, want boom", got.Items[0].Error)
	}
}

func TestCheckLogsListPagesNewestFirst(t *testing.T) {
	eng := testEngine(t, warden.Config{})
	var ids []string // index 0 is the newest
	for i := 0; i < 30; i++ {
		e := seedCheckLog(t, eng, &checklog.Entry{
			TenantID: "t1", Decision: "allow",
			CreatedAt: checkLogT0.Add(time.Duration(30-i) * time.Minute),
		})
		ids = append(ids, e.ID.String())
	}

	got, err := listCheckLogs(t, eng, "t1", CheckLogsListInput{PageRequest: PageRequest{Limit: 10, Offset: 20}})
	if err != nil {
		t.Fatalf("checkLogs.list: %v", err)
	}
	if len(got.Items) != 10 {
		t.Fatalf("got %d rows, want 10", len(got.Items))
	}
	if got.Total != 30 || got.Limit != 10 || got.Offset != 20 {
		t.Errorf("meta = total %d limit %d offset %d, want 30/10/20", got.Total, got.Limit, got.Offset)
	}
	if !reflect.DeepEqual(idsOf(got.Items), ids[20:30]) {
		t.Errorf("ids = %v, want the oldest ten newest-first %v", idsOf(got.Items), ids[20:30])
	}
}

func TestCheckLogsListEmptyPageIsAnEmptyArray(t *testing.T) {
	eng := testEngine(t, warden.Config{})
	got, err := listCheckLogs(t, eng, "t1", CheckLogsListInput{})
	if err != nil {
		t.Fatalf("checkLogs.list: %v", err)
	}
	raw, _ := json.Marshal(got)
	if !strings.Contains(string(raw), `"items":[]`) {
		t.Errorf("want items to marshal as [], got %s", raw)
	}
}

func TestCheckLogsListRefusals(t *testing.T) {
	eng := testEngine(t, warden.Config{})
	cases := []struct {
		name string
		in   CheckLogsListInput
		want string
	}{
		{"unknown decision", CheckLogsListInput{Decision: "denied"}, "decision is not one warden records: denied"},
		{"after not a time", CheckLogsListInput{After: "yesterday"}, "after is not an RFC 3339 time: yesterday"},
		{"before impossible date", CheckLogsListInput{Before: "2026-13-40T00:00:00Z"}, "before is not an RFC 3339 time: 2026-13-40T00:00:00Z"},
		{"after later than before", CheckLogsListInput{
			After: "2026-09-02T00:00:00Z", Before: "2026-09-01T00:00:00Z",
		}, "after is later than before"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := listCheckLogs(t, eng, "t1", tc.in)
			var ce *dashcontract.Error
			if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
				t.Fatalf("want BAD_REQUEST, got %v", err)
			}
			if ce.Message != tc.want {
				t.Errorf("message = %q, want %q", ce.Message, tc.want)
			}
		})
	}
}

func TestCheckLogsTenantIsolation(t *testing.T) {
	f := newCheckLogFixture(t)

	got, err := listCheckLogs(t, f.eng, "t1", CheckLogsListInput{})
	if err != nil {
		t.Fatalf("checkLogs.list: %v", err)
	}
	for _, it := range got.Items {
		if it.ID == f.other.ID.String() {
			t.Fatalf("t2 row %s leaked into a t1 list", it.ID)
		}
	}
	if got.Total != 2 {
		t.Errorf("t1 total = %d, want 2", got.Total)
	}

	_, err = checkLogsDetailHandler(Deps{Engine: f.eng})(context.Background(),
		CheckLogDetailInput{ID: f.other.ID.String()}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
		t.Fatalf("t1 reading a t2 row: want NOT_FOUND, got %v", err)
	}

	// And the owner can read it.
	if _, err := checkLogsDetailHandler(Deps{Engine: f.eng})(context.Background(),
		CheckLogDetailInput{ID: f.other.ID.String()}, principalFor("t2")); err != nil {
		t.Fatalf("t2 reading its own row: %v", err)
	}
}

func TestCheckLogsDetailReportsEveryField(t *testing.T) {
	eng := testEngine(t, warden.Config{})
	e := seedCheckLog(t, eng, &checklog.Entry{
		TenantID: "t1", NamespacePath: "eng", AppID: "app_1",
		SubjectKind: "user", SubjectID: "alice", Action: "delete",
		ResourceType: "document", ResourceID: "d9",
		Decision: "deny_explicit", Reason: "policy x denies",
		MatchedBy: []checklog.MatchRef{
			{Source: "abac", RuleID: "wpol_01abc", Detail: `policy "x" (deny)`},
		},
		Obligations: []string{"notify"},
		EvalTimeNs:  1234, RequestIP: "203.0.113.7", RequestID: "req-1", TraceID: "trace-1",
		Cached: true, Error: "", CreatedAt: checkLogT0,
	})

	got, err := checkLogsDetailHandler(Deps{Engine: eng})(context.Background(),
		CheckLogDetailInput{ID: e.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("checkLogs.detail: %v", err)
	}

	want := CheckLogDetail{
		CheckLogSummary: CheckLogSummary{
			ID: e.ID.String(), NamespacePath: "eng", SubjectKind: "user", SubjectID: "alice",
			Action: "delete", ResourceType: "document", ResourceID: "d9",
			Decision: "deny_explicit", Reason: "policy x denies", EvalTimeNs: 1234,
			Cached: true, CreatedAt: "2026-09-01T12:00:00Z",
		},
		AppID:       "app_1",
		MatchedBy:   []CheckLogMatch{{Source: "abac", RuleID: "wpol_01abc", Detail: `policy "x" (deny)`}},
		Obligations: []string{"notify"},
		RequestIP:   "203.0.113.7",
		RequestID:   "req-1",
		TraceID:     "trace-1",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("detail =\n%+v\nwant\n%+v", got, want)
	}
}

func TestCheckLogsDetailEmptyListsAreArraysNotNull(t *testing.T) {
	// The page must never have to tell "none" from "not sent", so an empty
	// matchedBy and obligations marshal as [] and not null.
	eng := testEngine(t, warden.Config{})
	e := seedCheckLog(t, eng, &checklog.Entry{TenantID: "t1", Decision: "allow", CreatedAt: checkLogT0})

	got, err := checkLogsDetailHandler(Deps{Engine: eng})(context.Background(),
		CheckLogDetailInput{ID: e.ID.String()}, principalFor("t1"))
	if err != nil {
		t.Fatalf("checkLogs.detail: %v", err)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	for _, frag := range []string{`"matchedBy":[]`, `"obligations":[]`} {
		if !strings.Contains(string(raw), frag) {
			t.Errorf("want %s in %s", frag, raw)
		}
	}
}

func TestCheckLogsDetailRefusals(t *testing.T) {
	eng := testEngine(t, warden.Config{})
	h := checkLogsDetailHandler(Deps{Engine: eng})

	// A policy id is well formed but not a check log id.
	_, err := h(context.Background(), CheckLogDetailInput{ID: "pol_123"}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
		t.Fatalf("pol_123: want BAD_REQUEST, got %v", err)
	}
	if ce.Message != "not a check log id: pol_123" {
		t.Errorf("message = %q", ce.Message)
	}
	for _, raw := range []string{"", "chklog", "garbage", id.NewPolicyID().String()} {
		_, err := h(context.Background(), CheckLogDetailInput{ID: raw}, principalFor("t1"))
		if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeBadRequest {
			t.Errorf("%q: want BAD_REQUEST, got %v", raw, err)
		}
	}

	// A well-formed id nobody wrote is NOT_FOUND, not BAD_REQUEST.
	_, err = h(context.Background(), CheckLogDetailInput{ID: id.NewCheckLogID().String()}, principalFor("t1"))
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeNotFound {
		t.Fatalf("unknown id: want NOT_FOUND, got %v", err)
	}
}

func TestCheckLogsListReportsWhatWasNotRecorded(t *testing.T) {
	eng := testEngine(t, warden.Config{})
	got, err := listCheckLogs(t, eng, "t1", CheckLogsListInput{})
	if err != nil {
		t.Fatalf("checkLogs.list: %v", err)
	}
	if got.NotRecorded == nil {
		t.Fatal("notRecorded is absent with check logging on")
	}
	if got.NotRecorded.QueueFull != 0 || got.NotRecorded.WriteFailed != 0 {
		t.Errorf("loss = %+v, want zeros", got.NotRecorded)
	}
	if _, err := time.Parse(time.RFC3339, got.NotRecorded.Since); err != nil {
		t.Errorf("since %q is not RFC 3339: %v", got.NotRecorded.Since, err)
	}
	raw, _ := json.Marshal(got)
	if !strings.Contains(string(raw), `"notRecorded":{`) {
		t.Errorf("want a notRecorded object in %s", raw)
	}
}

func TestCheckLogsListOmitsNotRecordedWhenLoggingIsOff(t *testing.T) {
	off := false
	eng := testEngine(t, warden.Config{EnableCheckLog: &off})
	got, err := listCheckLogs(t, eng, "t1", CheckLogsListInput{})
	if err != nil {
		t.Fatalf("checkLogs.list: %v", err)
	}
	if got.NotRecorded != nil {
		t.Errorf("notRecorded = %+v, want nil with check logging off", got.NotRecorded)
	}
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), "notRecorded") {
		t.Errorf("notRecorded key present in %s", raw)
	}
}

func TestCheckLogsHandlersRefuseWithoutAnEngine(t *testing.T) {
	_, err := checkLogsListHandler(Deps{})(context.Background(), CheckLogsListInput{}, principalFor("t1"))
	var ce *dashcontract.Error
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeUnavailable {
		t.Errorf("list: want UNAVAILABLE, got %v", err)
	}
	_, err = checkLogsDetailHandler(Deps{})(context.Background(), CheckLogDetailInput{}, principalFor("t1"))
	if !errorsAs(err, &ce) || ce.Code != dashcontract.CodeUnavailable {
		t.Errorf("detail: want UNAVAILABLE, got %v", err)
	}
}
