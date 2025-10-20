package cmd

import (
	"fmt"
	"io"
	"testing"
	"time"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
	"github.com/cilium/cilium/dnsproxy/utils"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
	grpc "google.golang.org/grpc"
)

// DummyUpdateMappingsClient is a dummy implementation of pb.FQDNData_UpdateMappingsClient.
type DummyUpdateMappingsClient struct {
	grpc.ClientStream
	sendChan chan *pb.AzureFQDNMapping
	recvChan chan *pb.Result
	closeCh  chan struct{}
}

func NewDummyUpdateMappingsClient() *DummyUpdateMappingsClient {
	return &DummyUpdateMappingsClient{
		sendChan: make(chan *pb.AzureFQDNMapping, 1),
		recvChan: make(chan *pb.Result, 1),
		closeCh:  make(chan struct{}),
	}
}

func (d *DummyUpdateMappingsClient) Send(msg *pb.AzureFQDNMapping) error {
	select {
	case d.sendChan <- msg:
		return nil
	case <-d.closeCh:
		return io.EOF
	}
}

func (d *DummyUpdateMappingsClient) Recv() (*pb.Result, error) {
	select {
	case res := <-d.recvChan:
		return res, nil
	case <-d.closeCh:
		return nil, fmt.Errorf("stream closed") // doesn't require connection reset
	}
}

func (d *DummyUpdateMappingsClient) CloseSend() error {
	return nil
}

// Test case 1: When a message is put on fqdnMappingChannel, client.SendMsg is eventually invoked on it.
func TestFqdnMappingStreamWrapper_SendMessage(t *testing.T) {
	dummyClient := NewDummyUpdateMappingsClient()
	connectionFixerLock := utils.NewErrorAwareLock(nil)
	wrapper := &FqdnMappingStreamWrapper{
		fqdnMappingStreamLock: utils.NewErrorAwareLock(nil),
		fqdnMappingStream:     dummyClient,
		fqdnMappingChannel:    make(chan *pb.AzureFQDNMapping, 1),
		connectionLock:        connectionFixerLock,
		log:                   hivetest.Logger(t),
	}

	message := &pb.AzureFQDNMapping{RequestId: 1}
	wrapper.fqdnMappingChannel <- message

	go wrapper.createFQDNMappingSenders()

	select {
	case sentMsg := <-dummyClient.sendChan:
		assert.Equal(t, message, sentMsg)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Expected message to be sent to the client")
	}
}

// Test case 2: When client.RecvMsg returns a message, and its id is a key in the key-value map fqdnMappingResponseChan,
// the message gets put on the channel that is the value in the map for that key.
func TestFqdnMappingStreamWrapper_ReceiveMessage(t *testing.T) {
	dummyClient := NewDummyUpdateMappingsClient()
	connectionFixerLock := utils.NewErrorAwareLock(nil)
	response := &pb.Result{RequestId: 1}
	wrapper := &FqdnMappingStreamWrapper{
		fqdnMappingStreamLock:   utils.NewErrorAwareLock(nil),
		fqdnMappingStream:       dummyClient,
		fqdnMappingResponseChan: lock.Map[uint32, chan *pb.Result]{},
		connectionLock:          connectionFixerLock,
		log:                     hivetest.Logger(t),
	}

	responseChan := make(chan *pb.Result, 1)
	wrapper.fqdnMappingResponseChan.Store(response.RequestId, responseChan)

	go func() {
		dummyClient.recvChan <- response
	}()
	go wrapper.ReceiveResponses()

	select {
	case res := <-responseChan:
		assert.Equal(t, response, res)
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Expected response to be sent to the response channel")
	}
}

// Test case 3: If client.SendMsg or client.RecvMsg return an error, the fqdnMappingStream is closed, and the trigger called.
func TestFqdnMappingStreamWrapper_HandleErrorInSend(t *testing.T) {
	dummyClient := NewDummyUpdateMappingsClient()
	resetCalled := make(chan bool, 1)
	connectionWatcher := NewConnectionWatcher(
		nil,
		func() error {
			resetCalled <- true
			return nil
		},
		hivetest.Logger(t),
	)

	wrapper := &FqdnMappingStreamWrapper{
		fqdnMappingStreamLock: utils.NewErrorAwareLock(nil),
		fqdnMappingStream:     dummyClient,
		fqdnMappingChannel:    make(chan *pb.AzureFQDNMapping, 1),
		streamResetComplete:   make(chan struct{}),
		log:                   hivetest.Logger(t),
		connectionLock:        connectionWatcher.connectionLock,
	}

	if connectionWatcher == nil {
		t.Fatalf("expected connectionWatcher to be non-nil")
	}

	triggerCalled := make(chan bool, 1)
	triggerFunc := func(reason string) {
		triggerCalled <- true
		wrapper.streamResetComplete <- struct{}{}
	}

	wrapper.createFQDNMappingStreamCleaner(triggerFunc)
	wrapper.createFQDNMappingSenders()
	dummyClient.sendChan <- &pb.AzureFQDNMapping{RequestId: 1} // send a message to fill the send channel
	close(dummyClient.closeCh)                                 // sends will fail

	message := &pb.AzureFQDNMapping{RequestId: 1}
	wrapper.fqdnMappingChannel <- message
	<-resetCalled
	<-triggerCalled
}

// Test case 3: If client.SendMsg or client.RecvMsg return an error, the fqdnMappingStream is closed, and the trigger called.
func TestFqdnMappingStreamWrapper_HandleErrorInRecv(t *testing.T) {
	dummyClient := NewDummyUpdateMappingsClient()
	wrapper := &FqdnMappingStreamWrapper{
		fqdnMappingStreamLock: utils.NewErrorAwareLock(nil),
		fqdnMappingStream:     dummyClient,
		log:                   hivetest.Logger(t),
		fqdnMappingChannel:    make(chan *pb.AzureFQDNMapping, 1),
		connectionLock:        utils.NewErrorAwareLock(nil),
	}

	triggerCalled := make(chan bool, 1)
	triggerFunc := func(reason string) {
		triggerCalled <- true
		wrapper.streamResetComplete <- struct{}{}
	}

	wrapper.createFQDNMappingStreamCleaner(triggerFunc)
	wrapper.createFqdnResponseReceiver()
	close(dummyClient.closeCh) // recvs will fail
	<-triggerCalled
}
