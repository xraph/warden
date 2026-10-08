package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden"
	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
	"github.com/xraph/warden/plugin"
)

func (a *API) registerAssignmentRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("assignments"))

	manage := a.authorize("manage", "warden:assignment")
	read := a.authorize("read", "warden:assignment")

	if err := g.POST("/assignments", a.assignRole,
		forge.WithSummary("Assign role"),
		forge.WithDescription("Assigns a role to a subject."),
		forge.WithOperationID("wardenAssignRole"),
		forge.WithRequestSchema(AssignRoleRequest{}),
		forge.WithCreatedResponse(&assignment.Assignment{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(manage),
	); err != nil {
		return err
	}

	if err := g.DELETE("/assignments/:assignmentId", a.unassignRole,
		forge.WithSummary("Unassign role"),
		forge.WithDescription("Removes a role assignment."),
		forge.WithOperationID("wardenUnassignRole"),
		forge.WithRequestSchema(GetAssignmentRequest{}),
		forge.WithNoContentResponse(),
		forge.WithErrorResponses(),
		forge.WithMiddleware(manage),
	); err != nil {
		return err
	}

	if err := g.GET("/assignments", a.listAssignments,
		forge.WithSummary("List assignments"),
		forge.WithOperationID("wardenListAssignments"),
		forge.WithRequestSchema(ListAssignmentsRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Assignment list", []*assignment.Assignment{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(read),
	); err != nil {
		return err
	}

	return g.GET("/subjects/:subjectKind/:subjectId/roles", a.listSubjectRoles,
		forge.WithSummary("List subject roles"),
		forge.WithDescription("Returns roles assigned to a subject."),
		forge.WithOperationID("wardenListSubjectRoles"),
		forge.WithRequestSchema(ListSubjectRolesRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Role IDs", []string{}),
		forge.WithErrorResponses(),
		forge.WithMiddleware(read),
	)
}

func (a *API) assignRole(ctx forge.Context, req *AssignRoleRequest) (*assignment.Assignment, error) {
	{
		verr := forge.NewValidationErrors()
		if req.RoleID == "" {
			verr.AddWithCode("role_id", "role_id is required", "REQUIRED", nil)
		}
		if req.SubjectKind == "" {
			verr.AddWithCode("subject_kind", "subject_kind is required", "REQUIRED", nil)
		} else if !validSubjectKind(req.SubjectKind) {
			verr.AddWithCode("subject_kind", "subject_kind must be one of user, api_key, service, service_acct", "ENUM", req.SubjectKind)
		}
		if req.SubjectID == "" {
			verr.AddWithCode("subject_id", "subject_id is required", "REQUIRED", nil)
		}
		if verr.HasErrors() {
			return nil, verr
		}
	}

	roleID, err := id.ParseRoleID(req.RoleID)
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid role_id: %v", err))
	}

	appID, tenantID := scopeFromForgeContext(ctx)
	actor, _ := warden.ActorFromContext(ctx.Context())
	now := time.Now()
	ass := &assignment.Assignment{
		ID:           id.NewAssignmentID(),
		TenantID:     tenantID,
		AppID:        appID,
		RoleID:       roleID,
		SubjectKind:  req.SubjectKind,
		SubjectID:    req.SubjectID,
		ResourceType: req.ResourceType,
		ResourceID:   req.ResourceID,
		GrantedBy:    actor.ID,
		CreatedAt:    now,
	}

	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			return nil, forge.BadRequest(fmt.Sprintf("invalid expires_at: %v", err))
		}
		ass.ExpiresAt = &t
	}

	// The member cap, checked the way the dashboard's assignments.create
	// checks it (assignment.CheckMemberCap): last, after every input check,
	// so a malformed request against a full role reports what is wrong with
	// it. A subject who already holds the role live is never refused. The
	// check and the insert are not atomic, so two concurrent creates can
	// take a role one past its cap.
	r, err := a.eng.Store().GetRole(ctx.Context(), tenantID, roleID)
	if err != nil {
		return nil, mapError(err)
	}
	if err := assignment.CheckMemberCap(ctx.Context(), a.eng.Store(), tenantID, r.ID, r.Name, r.MaxMembers,
		req.SubjectKind, req.SubjectID, now); err != nil {
		return nil, mapError(err)
	}

	if err := a.eng.Store().CreateAssignment(ctx.Context(), ass); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitRoleAssigned(ctx.Context(), ass)
		a.eng.Plugins().EmitAudit(ctx.Context(), plugin.Event{
			Actor: actor, At: now, Action: "assignment.created",
			TenantID: tenantID, EntityID: ass.ID.String(), Entity: ass,
		})
	}

	// Return nil as the value (not ass): Forge auto-serializes a non-nil
	// return at 200, which would double-write the body after this
	// explicit 201 write. See role_handler.go's createRole for the same
	// pattern, used everywhere a handler needs a non-200 status.
	return nil, ctx.JSON(http.StatusCreated, ass)
}

func (a *API) unassignRole(ctx forge.Context, _ *GetAssignmentRequest) (*struct{}, error) {
	assID, err := id.ParseAssignmentID(ctx.Param("assignmentId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid assignment ID: %v", err))
	}

	_, tenantID := scopeFromForgeContext(ctx)

	// Get before delete for hook.
	ass, getErr := a.eng.Store().GetAssignment(ctx.Context(), tenantID, assID)

	if err := a.eng.Store().DeleteAssignment(ctx.Context(), tenantID, assID); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		actor, _ := warden.ActorFromContext(ctx.Context())
		ev := plugin.Event{
			Actor: actor, At: time.Now(), Action: "assignment.deleted",
			TenantID: tenantID, EntityID: assID.String(),
		}
		if getErr == nil {
			a.eng.Plugins().EmitRoleUnassigned(ctx.Context(), ass)
			ev.Before = ass
		}
		a.eng.Plugins().EmitAudit(ctx.Context(), ev)
	}

	return nil, ctx.NoContent(http.StatusNoContent)
}

func (a *API) listAssignments(ctx forge.Context, req *ListAssignmentsRequest) (*AssignmentListResponse, error) {
	_, tenantID := scopeFromForgeContext(ctx)
	filter := &assignment.ListFilter{
		TenantID:    tenantID,
		SubjectKind: req.SubjectKind,
		SubjectID:   req.SubjectID,
		Limit:       defaultLimit(req.Limit),
		Offset:      req.Offset,
	}

	if req.RoleID != "" {
		rid, err := id.ParseRoleID(req.RoleID)
		if err != nil {
			return nil, forge.BadRequest(fmt.Sprintf("invalid role_id: %v", err))
		}
		filter.RoleID = &rid
	}

	assignments, err := a.eng.Store().ListAssignments(ctx.Context(), filter)
	if err != nil {
		return nil, mapError(err)
	}

	return &AssignmentListResponse{Body: assignments}, nil
}

func (a *API) listSubjectRoles(ctx forge.Context, _ *ListSubjectRolesRequest) (*SubjectRolesResponse, error) {
	_, tenantID := scopeFromForgeContext(ctx)
	subjectKind := ctx.Param("subjectKind")
	subjectID := ctx.Param("subjectId")

	// Pass nil to match assignments at any namespace within the tenant.
	roles, err := a.eng.Store().ListRolesForSubject(ctx.Context(), tenantID, nil, subjectKind, subjectID)
	if err != nil {
		return nil, mapError(err)
	}

	ids := make([]string, len(roles))
	for i, r := range roles {
		ids[i] = r.String()
	}

	return &SubjectRolesResponse{Body: ids}, nil
}
