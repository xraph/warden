// handlers_schema.go: the schema as Warden source. schema.export writes a
// tenant's state as canonical source, and schema.plan reports what applying
// an edited copy would do, without doing it.
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

// schemaReadGrants are the reads a caller needs for the schema intents, in
// the order a refusal names them. The first is the one the manifest gate
// enforces; it is asked again here so a handler called directly refuses the
// same way.
var schemaReadGrants = []string{
	"warden:role",
	"warden:permission",
	"warden:policy",
	"warden:resourcetype",
	"warden:relation",
}

// requireSchemaReads refuses with PERMISSION_DENIED naming the first read
// the caller lacks. An engine that cannot decide fails the request, as the
// authorizer does.
func requireSchemaReads(ctx context.Context, eng *warden.Engine, p dashcontract.Principal, tenantID string) error {
	for _, resource := range schemaReadGrants {
		held, err := principalHolds(ctx, eng, p, tenantID, "read", resource)
		if err != nil {
			return mapWardenError(err)
		}
		if !held {
			return &dashcontract.Error{
				Code:    dashcontract.CodePermissionDenied,
				Message: fmt.Sprintf("missing permission read on %s", resource),
			}
		}
	}
	return nil
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

		prog, diags := checkSource(in.Source, tenantID)
		if len(diags) > 0 {
			return invalidPlan(diags), nil
		}

		// TenantID wins over the header, and checkSource has already refused
		// a header that names another tenant, so this is always the caller's.
		res, err := dsl.Apply(ctx, deps.Engine, prog, dsl.ApplyOptions{
			TenantID: tenantID,
			DryRun:   true,
			Prune:    in.Prune,
		})
		if err != nil {
			var derr *dsl.DiagnosticError
			if errors.As(err, &derr) {
				return invalidPlan(schemaDiagnostics(derr.Diags)), nil
			}
			return SchemaPlanResponse{}, mapWardenError(err)
		}
		return SchemaPlanResponse{
			Valid:       true,
			Diagnostics: []SchemaDiagnostic{},
			Created:     nonNil(res.Created),
			Updated:     nonNil(res.Updated),
			Deleted:     nonNil(res.Deleted),
			NoOps:       res.NoOps,
			Digest:      planDigest(in.Prune, res),
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
// Order: syntax, then the two things the dashboard refuses outright (imports
// and another tenant), then the resolver. A parse failure stops there,
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
	if prog.Tenant != "" && prog.Tenant != tenantID {
		// Program keeps no position for the tenant line, so report the
		// header's. A program with no header position reports 1:1.
		pos := prog.HeaderPos
		line, col := pos.Line, pos.Col
		if line < 1 {
			line, col = 1, 1
		}
		refused = append(refused, SchemaDiagnostic{
			Line:    line,
			Col:     col,
			Message: fmt.Sprintf("this source names tenant %q; the dashboard applies to your tenant only", prog.Tenant),
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

// planDigest identifies one diff under one prune flag. It is SHA-256 over the
// prune flag, then each of created, updated and deleted sorted and
// length-prefixed (the count, then each line with its own length), then the
// no-op count, hex-encoded. Sorting makes it independent of the order the
// applier walked the store in; length prefixes keep ["x","y"] and ["xy"], or
// a line moving from one list to the next, from colliding.
//
// schema.apply recomputes it against the store as it is then, so an edit, or
// a change to the store since the plan was read, changes the digest and the
// apply is refused.
func planDigest(prune bool, r *dsl.ApplyResult) string {
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
