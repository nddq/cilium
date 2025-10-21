package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"github.com/go-openapi/runtime"
	"go.uber.org/goleak"

	"github.com/cilium/cilium/api/v1/dnsproxy/server/restapi/dnsproxy"
	"github.com/cilium/cilium/pkg/hive"
)

func TestReadiness(t *testing.T) {
	tt := []struct {
		name        string
		expected    int
		isConnected bool
	}{
		{
			name:        "Readiness check",
			expected:    http.StatusOK,
			isConnected: true,
		},
		{
			name:        "Readiness check failed",
			expected:    http.StatusInternalServerError,
			isConnected: false,
		},
	}
	for _, tc := range tt {
		t.Run(tc.name, func(t *testing.T) {
			defer goleak.VerifyNone(t)

			rr := httptest.NewRecorder()

			hive := hive.New(
				ReadinessHandlerCell(
					func() bool {
						return tc.isConnected
					},
				),

				// transform GetReady in a http.HandlerFunc to use
				// the http package testing facilities
				cell.Provide(func(h dnsproxy.GetReadyzHandler) http.HandlerFunc {
					return func(w http.ResponseWriter, _ *http.Request) {
						res := h.Handle(dnsproxy.GetReadyzParams{})
						res.WriteResponse(w, runtime.TextProducer())
					}
				}),

				cell.Invoke(func(hf http.HandlerFunc) {
					req := httptest.NewRequest(http.MethodGet, "http://localhost/readyz", nil)
					hf.ServeHTTP(rr, req)
				}),
			)

			tlog := hivetest.Logger(t)
			if err := hive.Start(tlog, context.Background()); err != nil {
				t.Fatalf("failed to start: %s", err)
			}

			if rr.Result().StatusCode != tc.expected {
				t.Fatalf("expected http status code %d, got %d", tc.expected, rr.Result().StatusCode)
			}

			if err := hive.Stop(tlog, context.Background()); err != nil {
				t.Fatalf("failed to stop: %s", err)
			}
		})
	}
}
