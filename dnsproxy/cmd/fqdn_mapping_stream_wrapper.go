package cmd

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"sync/atomic"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
	"github.com/cilium/cilium/dnsproxy/metrics"
	"github.com/cilium/cilium/dnsproxy/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/time"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FqdnMappingStreamWrapper wraps the FQDN mapping stream and provides a
// mechanism to send and receive messages on the stream. It also provides
// a mechanism to handle errors and recreate the stream if necessary.
// fqdnMappingStream is the stream used to send FQDN mappings to the cilium agent
// and receive acks
//
// fqdnMappingChannel is used to put the FQDN mappings to be sent to the cilium agent.
// This is done by goroutines created for each DNS requests. The mappings are read by
// the sender goroutines and sent to the cilium agent.
//
// fqdnMappingResponseChan is a map of dns message id to response channel. For each
// FQDN mapping sent to the cilium agent, a response channel is created and stored
// in the map. The response is sent to the channel when it is received from the cilium
// agent. The channel is deleted from the map when the response is received.
//
// fqdnMappingStreamLock is used to synchronize access to the stream.
//
// When an error occurs, the stream is marked as errored and the senders and
// receivers are blocked. The stream is cleaned up using Cilium triggers. Once the trigger
// is complete, streamResetComplete is used to signal that the stream has been cleaned up.
type FqdnMappingStreamWrapper struct {
	fqdnMappingStreamLock   *utils.ErrorAwareLock
	fqdnMappingStream       pb.AzureFQDNData_UpdateMappingsClient
	fqdnMappingChannel      chan *pb.AzureFQDNMapping
	fqdnMappingResponseChan lock.Map[uint32, chan *pb.Result]
	streamResetComplete     chan struct{}
	streamErrored           atomic.Bool
	connectionLock          *utils.ErrorAwareLock
	log                     *slog.Logger
}

// Number of senders to be created for sending FQDN mappings to the cilium agent.
const (
	SENDER_COUNT = 8
)

// NewFqdnMappingStreamWrapper creates a new FqdnMappingStreamWrapper instance.
// client is the FQDN data client used to create the stream.
// connectionResetFunction is the function to be called when the connection needs to be closed.
// triggerFunction is the function to be called when the stream needs to be recreated after closing.
func NewFqdnMappingStreamWrapper(
	client pb.AzureFQDNDataClient,
	connectionLock *utils.ErrorAwareLock,
	triggerFunction func(string),
	connectionCtx context.Context,
	log *slog.Logger,
) (*FqdnMappingStreamWrapper, error) {
	w := &FqdnMappingStreamWrapper{}
	w.log = log // Set logger FIRST before calling any methods that might log
	w.streamResetComplete = make(chan struct{})
	w.fqdnMappingStreamLock = utils.NewErrorAwareLock(nil)
	w.fqdnMappingChannel = make(chan *pb.AzureFQDNMapping)
	w.connectionLock = connectionLock
	w.streamErrored.Store(false)
	w.CreateFqdnMappingStreamIfNil(client, connectionCtx)
	w.createFQDNMappingSenders()
	w.createFqdnResponseReceiver()
	w.createFQDNMappingStreamCleaner(triggerFunction)
	return w, nil
}

// CreateFqdnMappingStreamIfNil creates the FQDN mapping stream if it is nil.
// It is used at initialization, and also to recreate the stream after errors.
func (w *FqdnMappingStreamWrapper) CreateFqdnMappingStreamIfNil(client pb.AzureFQDNDataClient, ctx context.Context) error {
	// Create the FQDN mapping stream
	if w.fqdnMappingStream == nil {
		ctx, cancel := context.WithCancel(ctx)
		w.fqdnMappingStreamLock.SetCancelUsers(cancel)
		st, err := client.UpdateMappings(ctx)
		if err != nil {
			w.log.Error("Failed to create FQDN mapping stream", logfields.Error, err)
			return err
		}
		w.fqdnMappingStream = st
		w.log.Info("Created new FQDN mapping stream")
	}

	return nil
}

// createFqdnResponseReceiver creates a goroutine to receive responses from the cilium agent.
// The responses are sent to the response channel that is stored in the map.
func (w *FqdnMappingStreamWrapper) createFqdnResponseReceiver() {
	go w.ReceiveResponses()
}

// MarkStreamAsErrored marks the stream as errored
func (w *FqdnMappingStreamWrapper) MarkStreamAsErrored(err error) {
	w.streamErrored.Store(true)
	w.fqdnMappingStreamLock.MarkResourceAsErrored(err)
}

// MarkStreamAsErrorFree marks the stream as error free
func (w *FqdnMappingStreamWrapper) MarkStreamAsErrorFree() {
	w.streamErrored.Store(false)
	w.fqdnMappingStreamLock.MarkResourceAsErrorFree()
}

// GetStreamErrored returns true if the stream is errored
func (w *FqdnMappingStreamWrapper) GetStreamErrored() bool {
	return w.streamErrored.Load()
}

// createFQDNMappingSenders creates the senders for sending FQDN mappings to the cilium agent.
func (w *FqdnMappingStreamWrapper) createFQDNMappingSenders() {
	for i := 0; i < SENDER_COUNT; i++ {
		go func() {
			for {
				w.log.Debug("Sender is waiting for message on the channel")
				message := <-w.fqdnMappingChannel
				w.log.Debug("Sender waiting for read lock to use the stream")
				w.fqdnMappingStreamLock.GetRLockIfResourceErrorFree()
				w.connectionLock.GetRLockIfResourceErrorFree()
				w.log.Debug("Sender has read locks, sending message")
				err := w.SendFqdnMapping(message)
				w.log.Debug("Unlocking stream and connection lock after sending message")
				w.connectionLock.RUnlock()
				w.fqdnMappingStreamLock.RUnlock()
				if err != nil {
					w.log.Error("Failed to send FQDN Mapping message", logfields.Error, err)
					w.MarkStreamAsErrored(err)
				}
			}
		}()
	}
}

// createFQDNMappingStreamCleaner creates a goroutine to clean up the FQDN mapping stream
// after errors are reported. The stream is recreated and the senders and receivers are
// unblocked. The trigger function is called to recreate the stream.
// The connectionResetFunction is called to reset the connection.
func (w *FqdnMappingStreamWrapper) createFQDNMappingStreamCleaner(
	triggerFunction func(string),
) {
	go func() {
		for {
			w.fqdnMappingStreamLock.GetLockIfResourceErrored()
			w.log.Info("Cleaning up FQDN mapping stream after errors reported")
			w.removeFqdnMappingStreamAndTriggerRecreation(triggerFunction, w.fqdnMappingStreamLock.GetErrorsNonLocking())
			<-w.streamResetComplete
			w.log.Info("FQDN stream clean up complete, marking as error free")
			w.MarkStreamAsErrorFree()
			w.log.Info("FQDN mapping stream marked as error free")
			w.fqdnMappingStreamLock.Unlock()
			w.log.Info("Unblocked senders and receivers")
		}
	}()
}

// ReceiveResponses receives responses from the cilium agent and sends them to the response channel.
func (w *FqdnMappingStreamWrapper) ReceiveResponses() {
	for {
		w.fqdnMappingStreamLock.GetRLockIfResourceErrorFree()
		w.connectionLock.GetRLockIfResourceErrorFree()
		w.log.Debug("Response receiver waiting for message on the stream")
		response, err := w.fqdnMappingStream.Recv()
		w.log.Debug("Unlocking stream and connection lock after receiving message")
		w.connectionLock.RUnlock()
		w.fqdnMappingStreamLock.RUnlock()

		if err != nil {
			if err == io.EOF || status.Code(err) == codes.Unavailable {
				w.log.Error("fqdn mapping stream closed", logfields.Error, err)
				w.MarkStreamAsErrored(err)
			} else {
				w.log.Error("Failed to receive response", logfields.Error, err)
				w.MarkStreamAsErrored(err)
			}
		}

		// Extract the dns message id from the response
		dnsMsgID := response.GetRequestId()

		// Get the response channel from the map
		responseChan, ok := w.fqdnMappingResponseChan.Load(dnsMsgID)
		if !ok {
			if metrics.CiliumAgentProcessingDelayed != nil {
				metrics.CiliumAgentProcessingDelayed.WithLabelValues().Inc()
			}
			w.log.Error("Response channel not found for dns message id", logfields.ID, dnsMsgID)
		} else {
			// Send the response to the response channel or else timeout after 100 milliseconds
			ticker := time.NewTicker(100 * time.Millisecond)
			select {
			case responseChan <- response:
				// Successfully sent the response
				w.log.Debug("Deleted response channel for dns message id", logfields.ID, dnsMsgID)

			case <-ticker.C:
				w.log.Warn("Timeout sending response for dns message id", logfields.ID, dnsMsgID)
			}
			ticker.Stop()

		}
		// Delete the response channel from the map
		w.fqdnMappingResponseChan.Delete(dnsMsgID)
		w.log.Debug("Deleted response channel for dns message id", logfields.ID, dnsMsgID)
	}
}

// AddFqdnMappingToSendChannelAndGetResponse adds the FQDN mapping to the send channel
// and waits for the response from the cilium agent.
func (w *FqdnMappingStreamWrapper) AddFqdnMappingToSendChannelAndGetResponse(message *pb.AzureFQDNMapping) error {
	if w.GetStreamErrored() {
		return fmt.Errorf("stream is errored, cannot send FQDN mapping")
	}

	// store the response channel with the key as dns message id
	responseChan := make(chan *pb.Result, 1)
	w.fqdnMappingResponseChan.Store(message.GetRequestId(), responseChan)
	w.log.Debug("Stored response channel for dns message id", logfields.ID, message.GetRequestId())

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	select {
	case w.fqdnMappingChannel <- message:

	case <-ticker.C:
		w.fqdnMappingResponseChan.Delete(message.GetRequestId())
		return fmt.Errorf("timeout sending fqdn mapping id on the channel: %d", message.GetRequestId())
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// Wait for the response from the cilium agent
	// 1. If the response is received, log the response
	// 2. If the context is cancelled, log the timeout
	select {
	case <-ctx.Done():
		w.log.Warn("Timeout waiting for result from FQDN mapping stream for request id", logfields.ID, message.GetRequestId())
		w.fqdnMappingResponseChan.Delete(message.GetRequestId())

		// Increment the timeout metric based on the message type
		msgType := "request"
		if message.GetMetrics() != nil && message.GetMetrics().GetDnsResponseData() != nil && message.GetMetrics().GetDnsResponseData().GetResponse() {
			msgType = "response"
		}
		metrics.CiliumAgentProcessingTimeout.WithLabelValues(msgType).Inc()
	case result := <-responseChan:
		w.log.Debug("Received result from FQDN mapping stream", logfields.ID, result.GetRequestId())
	}

	return nil
}

// SendFqdnMapping sends the FQDN mapping to the cilium agent.
func (w *FqdnMappingStreamWrapper) SendFqdnMapping(message *pb.AzureFQDNMapping) error {
	err := w.fqdnMappingStream.Send(message)
	if err != nil {
		if metrics.FQDNMappingSync != nil {
			metrics.FQDNMappingSync.WithLabelValues(err.Error()).Inc()
		}
	}

	return err
}

// removeFqdnMappingStreamAndTriggerRecreation removes the FQDN mapping stream and triggers
// the recreation of the stream. It is called when an error occurs and the stream needs to be recreated.
// The connectionResetFunction is called to close the connection and the triggerFunction
// is called to recreate the stream.
// The errs parameter is a list of errors that caused the stream to be recreated.
func (w *FqdnMappingStreamWrapper) removeFqdnMappingStreamAndTriggerRecreation(
	triggerFunction func(string),
	errs []error,
) {
	if errs == nil {
		return
	}

	connectionClosed := false
	reason := ""
	w.closeFqdnMappingStream()

	for _, err := range errs {
		if err == io.EOF || status.Code(err) == codes.Unavailable {
			w.log.Info("Connection cleanup required to fix FQDN mapping stream")
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
				reason = "Received EOF from FQDN mapping stream"
			} else {
				reason = "Received Unavailable from FQDN mapping stream"
			}
		} else {
			reason = "Failed to send FQDN mapping/receive response"
		}

		w.log.Info("Calling trigger function to recreate the stream")

		triggerFunction(reason)
		w.log.Error(reason, logfields.Error, err)
	}
}

// closeFqdnMappingStream closes the FQDN mapping stream and sets it to nil.
func (w *FqdnMappingStreamWrapper) closeFqdnMappingStream() {
	if w.fqdnMappingStream != nil {
		err := w.fqdnMappingStream.CloseSend()
		if err != nil {
			w.log.Error("Failed to close Fqdn mapping stream", logfields.Error, err)
		}

		w.log.Info("Closed Fqdn mapping stream")
		w.fqdnMappingStream = nil
	}
}
