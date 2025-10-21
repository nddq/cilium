package cmd

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"

	"github.com/cilium/cilium/dnsproxy/metrics"
	"github.com/cilium/cilium/dnsproxy/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
)

// DNSRulesStreamWrapper wraps the DNS rules stream and provides methods to manage it.
// It handles the creation, cleanup, and error handling of the stream.
// It also responsible for receiving DNS rules and sending them back to the proxy.
type DNSRulesStreamWrapper struct {
	// dnsRulesStreamLock is a lock for the DNS rules stream.
	// It is used to ensure that the stream is not accessed concurrently.
	dnsRulesStreamLock *utils.ErrorAwareLock

	// dnsRulesStream is the actual stream used to receive DNS rules.
	dnsRulesStream pb.AzureFQDNData_SubscribeToDNSRulesClient

	// streamResetComplete is a channel used to signal when the stream has been reset.
	// It is not used during the initial creation of the stream.
	streamResetComplete chan struct{}

	// streamErrored is a flag indicating whether the stream has encountered an error.
	streamErrored atomic.Bool

	// connectionLock is a lock for the connection.
	connectionLock *utils.ErrorAwareLock

	// log is a logger for the DNS rules stream wrapper.
	log *slog.Logger
}

// NewDNSRulesStreamWrapper creates a new DNSRulesStreamWrapper.
// It initializes the stream and sets up the necessary locks.
// Parameters:
// - client: the FQDNDataClient used to create the stream.
// - connectionLock: a lock for the connection.
// - triggerFunction: a function to trigger to recreate stream when it sees an error.
// - connectionCtx: the context used for the connection.
// - updateRules: a function to update the DNS rules when they are received to DNS proxy.
func NewDNSRulesStreamWrapper(
	client pb.AzureFQDNDataClient,
	connectionLock *utils.ErrorAwareLock,
	triggerFunction func(string),
	connectionCtx context.Context,
	updateRules func(*pb.DNSPolicyRules),
	log *slog.Logger,
) (*DNSRulesStreamWrapper, error) {
	w := &DNSRulesStreamWrapper{
		log: log,
	}
	w.streamResetComplete = make(chan struct{})
	w.dnsRulesStreamLock = utils.NewErrorAwareLock(nil)
	w.connectionLock = connectionLock
	w.CreateDNSRulesStreamIfNil(client, connectionCtx, true)
	w.createDNSRulesReceiver(updateRules)
	w.createDNSRulesStreamCleaner(triggerFunction)
	w.streamErrored.Store(false)
	return w, nil
}

// MarkStreamAsErrorFree marks the stream as error free.
func (w *DNSRulesStreamWrapper) MarkStreamAsErrorFree() {
	w.streamErrored.Store(false)
	w.dnsRulesStreamLock.MarkResourceAsErrorFree()
}

// MarkStreamAsErrored marks the stream as errored.
func (w *DNSRulesStreamWrapper) MarkStreamAsErrored(err error) {
	w.streamErrored.Store(true)
	w.dnsRulesStreamLock.MarkResourceAsErrored(err)
}

// createDNSRulesReceiver creates a goroutine that listens for messages on the DNS rules stream.
func (w *DNSRulesStreamWrapper) createDNSRulesReceiver(updateRules func(*pb.DNSPolicyRules)) {
	go func() {
		for {
			w.dnsRulesStreamLock.GetRLockIfResourceErrorFree()
			w.connectionLock.GetRLockIfResourceErrorFree()
			w.log.Debug("Response receiver waiting for message on the stream")
			newRules, err := w.dnsRulesStream.Recv()
			w.log.Debug("Unlocking stream and connection lock after receiving message")
			w.connectionLock.RUnlock()
			w.dnsRulesStreamLock.RUnlock()

			if err != nil {
				if err == io.EOF || status.Code(err) == codes.Unavailable {
					w.log.Error("DNS rules stream closed", logfields.Error, err)
					w.MarkStreamAsErrored(err)
				} else {
					w.log.Error("Failed to receive response", logfields.Error, err)
					w.MarkStreamAsErrored(err)
				}
			}

			w.log.Debug("Received DNS rule", logfields.DNSRules, newRules)
			updateRules(newRules)
		}
	}()
}

// createDNSRulesStreamCleaner creates a goroutine that cleans up the DNS rules stream after errors are reported.
func (w *DNSRulesStreamWrapper) createDNSRulesStreamCleaner(triggerFunction func(string)) {
	go func() {
		for {
			w.dnsRulesStreamLock.GetLockIfResourceErrored()
			w.log.Info("Cleaning up DNS rules stream after errors reported")
			w.removeDNSRulesStreamAndTriggerRecreation(triggerFunction, w.dnsRulesStreamLock.GetErrorsNonLocking())
			<-w.streamResetComplete
			w.log.Info("DNS rules stream clean up complete, marking as error free")
			w.MarkStreamAsErrorFree()
			w.log.Info("DNS rules stream marked as error free")
			w.dnsRulesStreamLock.Unlock()
			w.log.Info("Unblocked receivers")
		}
	}()
}

// CreateDNSRulesStreamIfNil creates a new DNS rules stream if it is nil.
// It is used at initialization, and also to recreate the stream after errors.
func (w *DNSRulesStreamWrapper) CreateDNSRulesStreamIfNil(
	client pb.AzureFQDNDataClient,
	connectionCtx context.Context,
	initial bool,
) error {
	if w.dnsRulesStream == nil {
		ctx, cancel := context.WithCancel(connectionCtx)
		w.dnsRulesStreamLock.SetCancelUsers(cancel)
		stream, err := client.SubscribeToDNSRules(ctx, &pb.Request{})
		if err != nil {
			metrics.RetrieveDNSRules.WithLabelValues(err.Error()).Inc()
			w.log.Error("Failed to subscribe to DNS rules", logfields.Error, err)
			return err
		}

		w.dnsRulesStream = stream
		w.log.Info("Created new DNS rules stream")

		// Mark the stream as reset complete
		if !initial {
			w.streamResetComplete <- struct{}{}
		}
		w.log.Info("DNS rules stream reset complete")
	}

	return nil
}

// removeDNSRulesStreamAndTriggerRecreation removes the DNS rules stream and triggers its recreation.
// It is called when the stream encounters an error or is closed.
// It also handles the connection cleanup if necessary.
func (w *DNSRulesStreamWrapper) removeDNSRulesStreamAndTriggerRecreation(
	triggerFunction func(string),
	errs []error,
) {
	if errs == nil {
		return
	}

	connectionClosed := false
	reason := ""
	w.closeDNSRulesStream()

	for _, err := range errs {
		if err == io.EOF || status.Code(err) == codes.Unavailable {
			w.log.Info("Connection cleanup required to fix DNS rules stream")
			if !connectionClosed {
				w.log.Info("Marking connection as errored", logfields.Value, w.connectionLock)
				w.connectionLock.MarkResourceAsErrored(err)
				w.log.Info("Waiting for connection to be closed")
				// Trick to wait for connection to be closed
				w.connectionLock.GetRLockIfResourceErrorFree()
				w.connectionLock.RUnlock()
				connectionClosed = true
			}
			if err == io.EOF {
				reason = "Received EOF from DNS rules stream"
			} else {
				reason = "Received Unavailable from DNS rules stream"
			}
		} else {
			reason = "Failed to receive DNS rules"
		}

		w.log.Info("Calling trigger function to recreate the stream")

		triggerFunction(reason)
		w.log.Error(reason, logfields.Error, err)
	}
}

// closeDNSRulesStream closes the DNS rules stream and sets it to nil.
func (w *DNSRulesStreamWrapper) closeDNSRulesStream() {
	if w.dnsRulesStream != nil {
		err := w.dnsRulesStream.CloseSend()
		if err != nil {
			w.log.Error("Failed to close DNS rules stream", logfields.Error, err)
		}
		w.dnsRulesStream = nil
	}
}
