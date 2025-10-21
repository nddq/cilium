package api

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/hivetest"
	"go.uber.org/goleak"

	dnsproxyApi "github.com/cilium/cilium/api/v1/dnsproxy/server"
	"github.com/cilium/cilium/pkg/hive"
)

func TestNewServer(t *testing.T) {
	defer goleak.VerifyNone(t)

	port := 9235
	hive := hive.New(

		ReadinessHandlerCell(
			func() bool {
				return true
			},
		),
		HealthHandlerCell(),
		cell.Provide(func() Config {
			return Config{
				StandaloneDNSProxyAPIServeAddr: "localhost:9235",
			}
		}),

		dnsproxyApi.SpecCell,
		cell.Provide(newServer),

		cell.Invoke(func(srv Server) {}),
	)

	tlog := hivetest.Logger(t)
	if err := hive.Start(tlog, context.Background()); err != nil {
		t.Fatalf("failed to start: %s", err)
	}

	if err := testEndpoint(t, port, "/readyz", http.StatusOK); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}
	if err := testEndpoint(t, port, "/healthz", http.StatusOK); err != nil {
		t.Fatalf("failed to query endpoint: %s", err)
	}
	if err := hive.Stop(tlog, context.Background()); err != nil {
		t.Fatalf("failed to stop: %s", err)
	}
}

func testEndpoint(t *testing.T, port int, path string, statusCode int) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(
		ctx,
		http.MethodGet,
		fmt.Sprintf("http://localhost:%d%s", port, path),
		nil,
	)
	if err != nil {
		return fmt.Errorf("failed to create http request: %w", err)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("http request for %s failed: %w", path, err)
	}
	defer res.Body.Close()

	if res.StatusCode != statusCode {
		return fmt.Errorf("expected http status code %d, got: %d", statusCode, res.StatusCode)
	}

	return nil
}
