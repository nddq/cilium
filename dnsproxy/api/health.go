package api

import (
	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/dnsproxy/server/restapi/dnsproxy"
)

func HealthHandlerCell() cell.Cell {
	return cell.Module(
		"health-handler",
		"Standalone DNS proxy health HTTP handler",

		cell.Provide(func() dnsproxy.GetHealthzHandler {
			return &healthHandler{}
		}),
	)
}

type healthHandler struct{}

func (h *healthHandler) Handle(params dnsproxy.GetHealthzParams) middleware.Responder {
	return dnsproxy.NewGetHealthzOK().WithPayload("ok")
}
