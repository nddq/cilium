package api

import (
	"errors"
	"log/slog"

	"github.com/cilium/hive/cell"
	"github.com/go-openapi/runtime/middleware"

	"github.com/cilium/cilium/api/v1/dnsproxy/server/restapi/dnsproxy"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type isConnectedFunc func() bool

func ReadinessHandlerCell(isConnected isConnectedFunc) cell.Cell {
	return cell.Module(
		"readiness-handler",
		"Standalone DNS proxy readiness HTTP handler",

		cell.Provide(func() dnsproxy.GetReadyzHandler {

			return &readinessHandler{
				log:         log,
				isConnected: isConnected,
			}
		}),
	)
}

type readinessHandler struct {
	log         *slog.Logger
	isConnected isConnectedFunc
}

func (r *readinessHandler) Handle(params dnsproxy.GetReadyzParams) middleware.Responder {
	if err := r.checkStatus(); err != nil {
		r.log.Warn("Readiness check failed", logfields.Error, err)
		return dnsproxy.NewGetReadyzInternalServerError().WithPayload(err.Error())
	}

	return dnsproxy.NewGetReadyzOK().WithPayload("ok")
}

// checkStatus verifies the connection to cilium agent is healthy.
func (l *readinessHandler) checkStatus() error {
	l.log.Debug("Checking readiness status")
	if l.isConnected() {
		return nil
	}
	return errors.New("not ready")
}
