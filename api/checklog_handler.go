package api

import (
	"net/http"
	"time"

	"github.com/xraph/forge"

	"github.com/xraph/warden/checklog"
)

func (a *API) registerCheckLogRoutes(router forge.Router) error {
	g := router.Group("/v1", forge.WithGroupTags("check-logs"))

	return g.GET("/check-logs", a.listCheckLogs,
		forge.WithSummary("Query check logs"),
		forge.WithDescription("Returns authorization check audit logs with optional filters."),
		forge.WithOperationID("listCheckLogs"),
		forge.WithRequestSchema(ListCheckLogsRequest{}),
		forge.WithResponseSchema(http.StatusOK, "Check log list", []*checklog.Entry{}),
		forge.WithErrorResponses(),
	)
}

func (a *API) listCheckLogs(ctx forge.Context, req *ListCheckLogsRequest) ([]*checklog.Entry, error) {
	filter := &checklog.QueryFilter{
		SubjectKind:  req.SubjectKind,
		SubjectID:    req.SubjectID,
		Action:       req.Action,
		ResourceType: req.ResourceType,
		Decision:     req.Decision,
		Limit:        defaultLimit(req.Limit),
		Offset:       req.Offset,
	}

	if req.After != "" {
		t, err := time.Parse(time.RFC3339, req.After)
		if err != nil {
			return nil, forge.BadRequest("invalid after timestamp")
		}
		filter.After = &t
	}
	if req.Before != "" {
		t, err := time.Parse(time.RFC3339, req.Before)
		if err != nil {
			return nil, forge.BadRequest("invalid before timestamp")
		}
		filter.Before = &t
	}

	logs, err := a.eng.Store().ListCheckLogs(ctx.Context(), filter)
	if err != nil {
		return nil, mapError(err)
	}

	return logs, ctx.JSON(http.StatusOK, logs)
}
