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
	"github.com/cilium/cilium/pkg/safeio"
)

func TestHeatlhzHandler(t *testing.T) {
	defer goleak.VerifyNone(t)

	rr := httptest.NewRecorder()

	hive := hive.New(
		HealthHandlerCell(),

		// transform GetHealthzHandler in a http.HandlerFunc to use
		// the http package testing facilities
		cell.Provide(func(l dnsproxy.GetHealthzHandler) http.HandlerFunc {
			return func(w http.ResponseWriter, _ *http.Request) {
				res := l.Handle(dnsproxy.GetHealthzParams{})
				res.WriteResponse(w, runtime.TextProducer())
			}
		}),

		cell.Invoke(func(hf http.HandlerFunc) {
			req := httptest.NewRequest(http.MethodGet, "http://localhost/healthz", nil)
			hf.ServeHTTP(rr, req)
		}),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected http status code %d, got %d", http.StatusOK, rr.Result().StatusCode)
	}

	body, err := safeio.ReadAllLimit(rr.Result().Body, safeio.KB)
	if err != nil {
		t.Fatalf("error while reading response body: %s", err)
	}
	rr.Result().Body.Close()

	if string(body) != "ok" {
		t.Fatalf("expected response body %q, got: %q", "ok", string(body))
	}

	if err := hive.Stop(tlog, context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}
