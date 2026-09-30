// handlers_schema.go: the schema as Warden source. schema.export writes a
// tenant's state as canonical source, schema.plan reports what applying an
// edited copy would do without doing it, and schema.apply does it, but only
// as planned: it re-plans and refuses unless the digest the operator saw
// still matches.
//
// Both wrap the dsl package. The dashboard never reads a file, so anything
// the file loader would supply is refused instead: imports, because there is
// nothing to resolve them against, and a `tenant` that is not the caller's,
// because the dashboard applies to the caller's tenant only and a source that
// says otherwise is either a mistake or an attempt to aim at another tenant.
// Variable placeholders (`${NAME}`) are refused by the lexer itself: it has
// no `$` token, so the parser reports the character where it stands.
//
// The two intents are gated on read of warden:role, which intentPolicies
// enforces, and they return warden:permission, warden:policy,
// warden:resourcetype and warden:relation rows as source. The handler asks
// for those reads itself, as subjects.detail does, so a caller who may read
// roles cannot read the rest through this door.
package contract

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/xraph/warden"
	"github.com/xraph/warden/dsl"

	dashcontract "github.com/xraph/forge/extensions/dashboard/contract"
)

// schemaFile names the source in diagnostics. The wire form drops it.
const schemaFile = "schema.warden"

// SchemaExportInput is the schema.export request.
type SchemaExportInput struct {
	// NamespacePrefix limits the export to that namespace and below. "" is
	// every namespace.
	NamespacePrefix string `json:"namespacePrefix,omitempty"`
}

// SchemaExportResponse is the schema.export reply.
type SchemaExportResponse struct {
	Source string `json:"source"`
}

// SchemaDiagnostic is one problem with submitted source.
type SchemaDiagnostic struct {
	Line    int    `json:"line"` // 1-based
	Col     int    `json:"col"`  // 1-based byte column, as dsl.Pos
	Message string `json:"message"`
}

// SchemaApplyInput is the schema.apply request.
type SchemaApplyInput struct {
	Source string `json:"source"`
	Prune  bool   `json:"prune"`
	// Digest is the plan digest the operator saw.
	Digest string `json:"digest"`
}

// SchemaApplyResponse is the schema.apply reply: what was written.
type SchemaApplyResponse struct {
	Created []string `json:"created"`
	Updated []string `json:"updated"`
	Deleted []string `json:"deleted"`
	NoOps   int      `json:"noOps"`
	// Diverged is true when what was written differs from the plan the
	// digest vouched for. The digest is checked before the write and the
	// write is a second read of the store, so a change in between can make
	// the two differ. The lists are what was actually written.
	Diverged bool `json:"diverged"`
}

// schemaApplyStartedEvent is the entity of the schema.apply.started audit
// event: the counts the apply is about to attempt, as planned.
type schemaApplyStartedEvent struct {
	Created int  `json:"created"`
	Updated int  `json:"updated"`
	Deleted int  `json:"deleted"`
	NoOps   int  `json:"noOps"`
	Prune   bool `json:"prune"`
}

// schemaAppliedEvent is the entity of the schema.applied audit event: how
// the apply ended and the counts actually written. The per-entity events the
// applier emits under its own actor are separate; these two name the
// operator.
type schemaAppliedEvent struct {
	// Outcome is "succeeded" or "failed".
	Outcome  string `json:"outcome"`
	Error    string `json:"error,omitempty"`
	Created  int    `json:"created"`
	Updated  int    `json:"updated"`
	Deleted  int    `json:"deleted"`
	NoOps    int    `json:"noOps"`
	Prune    bool   `json:"prune"`
	Diverged bool   `json:"diverged"`
}

// SchemaPlanInput is the schema.plan request.
type SchemaPlanInput struct {
	Source string `json:"source"`
	Prune  bool   `json:"prune"`
}

// SchemaPlanResponse is the schema.plan reply.
type SchemaPlanResponse struct {
	// Valid is false when Diagnostics is non-empty; then the lists are empty
	// and Digest is "".
	Valid       bool               `json:"valid"`
	Diagnostics []SchemaDiagnostic `json:"diagnostics"`
	Created     []string           `json:"created"`
	Updated     []string           `json:"updated"`
	Deleted     []string           `json:"deleted"`
	NoOps       int                `json:"noOps"`
	// Digest identifies this exact diff and prune flag; schema.apply
	// requires it.
	Digest string `json:"digest"`
}

// schemaGrantResources are the resources a caller needs the intent's action
// on, in the order a refusal names them: read for export and plan, manage for
// apply. The first is the one the manifest gate enforces; it is asked again
// here so a handler called directly refuses the same way.
var schemaGrantResources = []string{
	"warden:role",
	"warden:permission",
	"warden:policy",
	"warden:resourcetype",
	"warden:relation",
}

// requireSchemaGrants refuses with PERMISSION_DENIED naming the first
// resource the caller lacks action on. An engine that cannot decide fails the
// request, as the authorizer does.
func requireSchemaGrants(ctx context.Context, eng *warden.Engine, p dashcontract.Principal, tenantID, action string) error {
	for _, resource := range schemaGrantResources {
		held, err := principalHolds(ctx, eng, p, tenantID, action, resource)
		if err != nil {
			return mapWardenError(err)
		}
		if !held {
			return &dashcontract.Error{
				Code:    dashcontract.CodePermissionDenied,
				Message: fmt.Sprintf("missing permission %s on %s", action, resource),
			}
		}
	}
	return nil
}

// requireSchemaReads is requireSchemaGrants for the read intents.
func requireSchemaReads(ctx context.Context, eng *warden.Engine, p dashcontract.Principal, tenantID string) error {
	return requireSchemaGrants(ctx, eng, p, tenantID, "read")
}

func schemaExportHandler(deps Deps) func(context.Context, SchemaExportInput, dashcontract.Principal) (SchemaExportResponse, error) {
	return func(ctx context.Context, in SchemaExportInput, p dashcontract.Principal) (SchemaExportResponse, error) {
		if err := requireEngine(deps); err != nil {
			return SchemaExportResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return SchemaExportResponse{}, err
		}
		if in.NamespacePrefix != "" {
			if err := validateNamespace(in.NamespacePrefix); err != nil {
				return SchemaExportResponse{}, err
			}
		}
		if err := requireSchemaReads(ctx, deps.Engine, p, tenantID); err != nil {
			return SchemaExportResponse{}, err
		}
		prog, err := dsl.BuildProgram(ctx, deps.Engine, dsl.ExportOptions{
			TenantID:        tenantID,
			NamespacePrefix: in.NamespacePrefix,
		})
		if err != nil {
			return SchemaExportResponse{}, mapWardenError(err)
		}
		return SchemaExportResponse{Source: dsl.Format(prog)}, nil
	}
}

func schemaPlanHandler(deps Deps) func(context.Context, SchemaPlanInput, dashcontract.Principal) (SchemaPlanResponse, error) {
	return func(ctx context.Context, in SchemaPlanInput, p dashcontract.Principal) (SchemaPlanResponse, error) {
		if err := requireEngine(deps); err != nil {
			return SchemaPlanResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return SchemaPlanResponse{}, err
		}
		if err := requireSchemaReads(ctx, deps.Engine, p, tenantID); err != nil {
			return SchemaPlanResponse{}, err
		}

		_, res, diags, err := dryRunSchema(ctx, deps, tenantID, in.Source, in.Prune)
		if err != nil {
			return SchemaPlanResponse{}, err
		}
		if len(diags) > 0 {
			return invalidPlan(diags), nil
		}
		return SchemaPlanResponse{
			Valid:       true,
			Diagnostics: []SchemaDiagnostic{},
			Created:     nonNil(res.Created),
			Updated:     nonNil(res.Updated),
			Deleted:     nonNil(res.Deleted),
			NoOps:       res.NoOps,
			Digest:      planDigest(in.Prune, in.Source, res),
		}, nil
	}
}

// dryRunSchema checks src and plans it against the store without writing. It
// is the one path schema.plan and schema.apply share, so the diff an operator
// sees and the diff apply verifies cannot come from different code. It
// returns the program and result when there are no diagnostics.
func dryRunSchema(ctx context.Context, deps Deps, tenantID, src string, prune bool) (*dsl.Program, *dsl.ApplyResult, []SchemaDiagnostic, error) {
	prog, diags := checkSource(src, tenantID)
	if len(diags) > 0 {
		return nil, nil, diags, nil
	}
	// TenantID wins over the header, and checkSource has already refused a
	// header that names another tenant, so this is always the caller's.
	res, err := dsl.Apply(ctx, deps.Engine, prog, dsl.ApplyOptions{
		TenantID: tenantID,
		DryRun:   true,
		Prune:    prune,
	})
	if err != nil {
		var derr *dsl.DiagnosticError
		if errors.As(err, &derr) {
			return nil, nil, schemaDiagnostics(derr.Diags), nil
		}
		return nil, nil, nil, mapWardenError(err)
	}
	return prog, res, nil, nil
}

// errSchemaChanged is the refusal for a digest that does not match the plan
// apply just computed, for any reason: the store changed, the source or the
// prune flag is not the one planned, or there was no plan.
func errSchemaChanged() error {
	return &dashcontract.Error{
		Code:    dashcontract.CodeConflict,
		Message: "the schema changed since you planned: plan again",
	}
}

func schemaApplyHandler(deps Deps) func(context.Context, SchemaApplyInput, dashcontract.Principal) (SchemaApplyResponse, error) {
	return func(ctx context.Context, in SchemaApplyInput, p dashcontract.Principal) (SchemaApplyResponse, error) {
		if err := requireEngine(deps); err != nil {
			return SchemaApplyResponse{}, err
		}
		tenantID, err := tenantFrom(p, deps)
		if err != nil {
			return SchemaApplyResponse{}, err
		}
		if err := requireSchemaGrants(ctx, deps.Engine, p, tenantID, "manage"); err != nil {
			return SchemaApplyResponse{}, err
		}

		// Invalid source is refused before the digest is looked at: there is
		// nothing to plan, so nothing the operator could have seen.
		prog, planned, diags, err := dryRunSchema(ctx, deps, tenantID, in.Source, in.Prune)
		if err != nil {
			return SchemaApplyResponse{}, err
		}
		if len(diags) > 0 {
			d := diags[0]
			return SchemaApplyResponse{}, badRequest(fmt.Sprintf(
				"the source has an error at line %d, column %d: %s", d.Line, d.Col, d.Message))
		}
		// The operator applies the diff they saw or nothing. The digest
		// covers the source, so the same lines with different values do not
		// match. An empty digest never matches: planDigest is always 64 hex
		// characters.
		plannedDigest := planDigest(in.Prune, in.Source, planned)
		if in.Digest == "" || in.Digest != plannedDigest {
			return SchemaApplyResponse{}, errSchemaChanged()
		}

		// Every check has passed. From here a failure leaves a partial apply,
		// so the audit trail names the operator before the first write and
		// again at the end, whichever way it ends.
		ctx = withActor(ctx, p)
		emitAudit(ctx, deps, p, "schema.apply.started", tenantID, tenantID, schemaApplyStartedEvent{
			Created: len(planned.Created),
			Updated: len(planned.Updated),
			Deleted: len(planned.Deleted),
			NoOps:   planned.NoOps,
			Prune:   in.Prune,
		}, nil)

		res, err := dsl.Apply(ctx, deps.Engine, prog, dsl.ApplyOptions{
			TenantID: tenantID,
			Prune:    in.Prune,
		})
		if err != nil {
			// The dry run passed, so anything that fails now failed after
			// other writes: what the applier wrote before it stays written
			// (the store has no transaction). Every error, a diagnostic
			// included (a grant whose permission vanished after the plan),
			// is a half apply, not a clean refusal.
			done := schemaAppliedEvent{Outcome: "failed", Error: err.Error(), Prune: in.Prune}
			if res != nil {
				done.Created, done.Updated, done.Deleted, done.NoOps = len(res.Created), len(res.Updated), len(res.Deleted), res.NoOps
			}
			emitAudit(ctx, deps, p, "schema.applied", tenantID, tenantID, done, nil)
			return SchemaApplyResponse{}, &dashcontract.Error{
				Code:    dashcontract.CodeInternal,
				Message: "the apply stopped part way: " + err.Error(),
			}
		}

		diverged := planDigest(in.Prune, in.Source, res) != plannedDigest
		emitAudit(ctx, deps, p, "schema.applied", tenantID, tenantID, schemaAppliedEvent{
			Outcome:  "succeeded",
			Created:  len(res.Created),
			Updated:  len(res.Updated),
			Deleted:  len(res.Deleted),
			NoOps:    res.NoOps,
			Prune:    in.Prune,
			Diverged: diverged,
		}, nil)
		return SchemaApplyResponse{
			Created:  nonNil(res.Created),
			Updated:  nonNil(res.Updated),
			Deleted:  nonNil(res.Deleted),
			NoOps:    res.NoOps,
			Diverged: diverged,
		}, nil
	}
}

// invalidPlan is the reply for source that cannot be planned: the lists are
// present and empty so they marshal as [] rather than null.
func invalidPlan(diags []SchemaDiagnostic) SchemaPlanResponse {
	return SchemaPlanResponse{
		Valid:       false,
		Diagnostics: diags,
		Created:     []string{},
		Updated:     []string{},
		Deleted:     []string{},
	}
}

func nonNil(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func schemaDiagnostics(in []*dsl.Diagnostic) []SchemaDiagnostic {
	out := make([]SchemaDiagnostic, 0, len(in))
	for _, d := range in {
		out = append(out, SchemaDiagnostic{Line: d.Pos.Line, Col: d.Pos.Col, Message: d.Msg})
	}
	return out
}

// checkSource parses and checks submitted source for tenantID. It returns
// the program when there are no diagnostics; otherwise the program is nil and
// the diagnostics say why. schema.apply runs the same check, so a plan and
// the apply it leads to cannot disagree about what is acceptable.
//
// Order: syntax, then the things the dashboard refuses outright (imports,
// another tenant, an app), then the resolver. A parse failure stops there,
// because the program is partial and the later checks would report noise.
func checkSource(src string, tenantID string) (*dsl.Program, []SchemaDiagnostic) {
	prog, errs := dsl.Parse(schemaFile, []byte(src))
	if len(errs) > 0 {
		return nil, schemaDiagnostics(errs)
	}

	var refused []SchemaDiagnostic
	if len(prog.Imports) > 0 {
		pos := prog.Imports[0].Pos
		refused = append(refused, SchemaDiagnostic{
			Line:    pos.Line,
			Col:     pos.Col,
			Message: "imports are not supported here: paste the imported source instead",
		})
	}
	// Program keeps no position for the tenant or app lines, so both report
	// the header's. A program with no header position reports 1:1.
	headerLine, headerCol := prog.HeaderPos.Line, prog.HeaderPos.Col
	if headerLine < 1 {
		headerLine, headerCol = 1, 1
	}
	if prog.Tenant != "" && prog.Tenant != tenantID {
		refused = append(refused, SchemaDiagnostic{
			Line:    headerLine,
			Col:     headerCol,
			Message: fmt.Sprintf("this source names tenant %q; the dashboard applies to your tenant only", prog.Tenant),
		})
	}
	// The dashboard sets no app, and Apply would otherwise stamp the source's
	// onto every entity it writes.
	if prog.App != "" {
		refused = append(refused, SchemaDiagnostic{
			Line:    headerLine,
			Col:     headerCol,
			Message: fmt.Sprintf("this source names app %q; the dashboard does not set an app: remove the declaration", prog.App),
		})
	}
	if len(refused) > 0 {
		sort.SliceStable(refused, func(i, j int) bool {
			if refused[i].Line != refused[j].Line {
				return refused[i].Line < refused[j].Line
			}
			return refused[i].Col < refused[j].Col
		})
		return nil, refused
	}

	if errs := dsl.Resolve(prog); len(errs) > 0 {
		return nil, schemaDiagnostics(errs)
	}
	return prog, nil
}

// planDigest identifies one diff, for one source, under one prune flag. It is
// SHA-256 over: the prune flag; the SHA-256 of the submitted source; then each
// of created, updated and deleted sorted and length-prefixed (the count, then
// each line with its own length); then the no-op count; hex-encoded.
//
// The source is in it because a `~` line names the fields that change and
// not their values: two sources can give the same lines and mean very
// different things, and the operator approved the one they saw. The source
// hash is fixed width, so it cannot run into the lists after it. The lists
// are sorted so the digest does not depend on the order the applier walked
// the store in, and length prefixes keep ["x","y"] and ["xy"], or a line
// moving from one list to the next, from colliding.
//
// schema.apply recomputes it against the store as it is then, so an edit, or
// a change to the store since the plan was read, changes the digest and the
// apply is refused.
func planDigest(prune bool, source string, r *dsl.ApplyResult) string {
	h := sha256.New()
	var buf [8]byte
	putUint := func(n uint64) {
		binary.BigEndian.PutUint64(buf[:], n)
		h.Write(buf[:])
	}
	if prune {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	srcSum := sha256.Sum256([]byte(source))
	h.Write(srcSum[:])
	for _, list := range [][]string{r.Created, r.Updated, r.Deleted} {
		lines := append([]string(nil), list...)
		sort.Strings(lines)
		putUint(uint64(len(lines)))
		for _, line := range lines {
			putUint(uint64(len(line)))
			h.Write([]byte(line))
		}
	}
	putUint(uint64(r.NoOps))
	return hex.EncodeToString(h.Sum(nil))
}
