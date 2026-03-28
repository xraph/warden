package api

import (
	"fmt"
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden/assignment"
	"github.com/xraph/warden/id"
)

func (a *API) registerAssignmentRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("assignments"))

	if err := g.POST("/assignments", a.assignRole,
		forge.WithSummary("Assign role"),
		forge.WithDescription("Assigns a role to a subject."),
		forge.WithOperationID("wardenAssignRole"),
		forge.WithRequestSchema(AssignRoleRequest{}),
		forge.WithCreatedResponse(&assignment.Assignment{}),
		forge.WithErrorResponses(),
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
	); err != nil {
		return err
	}

	if err := g.GET("/assignments", a.listAssignments,
		forge.WithSummary("List assignments"),
		forge.WithOperationID("wardenListAssignments"),
		forge.WithRequestSchema(ListAssignmentsRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Assignment list", []*assignment.Assignment{}),
		forge.WithErrorResponses(),
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
		CreatedAt:    now,
	}

	if req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, req.ExpiresAt)
		if err != nil {
			return nil, forge.BadRequest(fmt.Sprintf("invalid expires_at: %v", err))
		}
		ass.ExpiresAt = &t
	}

	if err := a.eng.Store().CreateAssignment(ctx.Context(), ass); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil {
		a.eng.Plugins().EmitRoleAssigned(ctx.Context(), ass)
	}

	return ass, ctx.JSON(http.StatusCreated, ass)
}

func (a *API) unassignRole(ctx forge.Context, _ *GetAssignmentRequest) (*struct{}, error) {
	assID, err := id.ParseAssignmentID(ctx.Param("assignmentId"))
	if err != nil {
		return nil, forge.BadRequest(fmt.Sprintf("invalid assignment ID: %v", err))
	}

	// Get before delete for hook.
	ass, getErr := a.eng.Store().GetAssignment(ctx.Context(), assID)

	if err := a.eng.Store().DeleteAssignment(ctx.Context(), assID); err != nil {
		return nil, mapError(err)
	}

	if a.eng.Plugins() != nil && getErr == nil {
		a.eng.Plugins().EmitRoleUnassigned(ctx.Context(), ass)
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

	roles, err := a.eng.Store().ListRolesForSubject(ctx.Context(), tenantID, subjectKind, subjectID)
	if err != nil {
		return nil, mapError(err)
	}

	ids := make([]string, len(roles))
	for i, r := range roles {
		ids[i] = r.String()
	}

	return &SubjectRolesResponse{Body: ids}, nil
}
