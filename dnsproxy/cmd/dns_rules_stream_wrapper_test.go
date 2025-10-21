package cmd

import (
	"fmt"
	"io"
	"testing"
	"time"

	"google.golang.org/grpc"

	pb "github.com/cilium/cilium/api/v1/dnsproxy"
	"github.com/cilium/cilium/dnsproxy/utils"
	"github.com/cilium/hive/hivetest"
	"github.com/stretchr/testify/assert"
)

// DummyDNSRulesClient is a dummy implementation of pb.FQDNData_SubscribeToDNSRulesClient.
type DummyDNSRulesClient struct {
	grpc.ClientStream
	recvChan chan *pb.DNSPolicyRules
	closeCh  chan struct{}
	errCh    chan struct{}
}

func NewDummyDNSRulesClient() *DummyDNSRulesClient {
	return &DummyDNSRulesClient{
		recvChan: make(chan *pb.DNSPolicyRules, 1),
		closeCh:  make(chan struct{}),
		errCh:    make(chan struct{}),
	}
}

func (d *DummyDNSRulesClient) Recv() (*pb.DNSPolicyRules, error) {
	select {
	case res := <-d.recvChan:
		return res, nil
	case <-d.closeCh:
		return nil, fmt.Errorf("stream closed") // doesn't require connection reset
	case <-d.errCh:
		return nil, io.EOF
	}
}

func (d *DummyDNSRulesClient) CloseSend() error {
	return nil
}

// Test case 1: When server sends a message, the client receives it and calls the updateRules function.
func TestDNSRulesStreamWrapper_ReceiveMessage(t *testing.T) {
	dummyClient := NewDummyDNSRulesClient()
	connectionFixerLock := utils.NewErrorAwareLock(nil)
	response := &pb.DNSPolicyRules{EndpointId: 123}
	wrapper := &DNSRulesStreamWrapper{
		dnsRulesStreamLock: utils.NewErrorAwareLock(nil),
		dnsRulesStream:     dummyClient,
		connectionLock:     connectionFixerLock,
		log:                hivetest.Logger(t),
	}
	called := make(chan bool, 1)
	updateRules := func(rules *pb.DNSPolicyRules) {
		// This is a dummy function to satisfy the interface
		// In a real scenario, this would update the DNS rules
		assert.Equal(t, response, rules)
		assert.Equal(t, uint64(123), rules.GetEndpointId())
		called <- true

	}
	go func() {
		dummyClient.recvChan <- response
	}()
	wrapper.createDNSRulesReceiver(updateRules)
	select {
	case <-called:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Expected message to be recv by the client")
	}
}

// Test case 2: If client.Recv return an error, the DNSRulesStreams is closed, and the trigger called.
func TestDNSRulesStreamWrapper_HandleErrorInRecv(t *testing.T) {
	dummyClient := NewDummyDNSRulesClient()
	wrapper := &DNSRulesStreamWrapper{
		dnsRulesStreamLock: utils.NewErrorAwareLock(nil),
		dnsRulesStream:     dummyClient,
		connectionLock:     utils.NewErrorAwareLock(nil),
		log: 			  hivetest.Logger(t),
	}

	updateRules := func(rules *pb.DNSPolicyRules) {
		// This is a dummy function to satisfy the interface
		// In a real scenario, this would update the DNS rules
	}
	triggerCalled := make(chan bool, 1)
	triggerFunc := func(reason string) {
		triggerCalled <- true
		wrapper.streamResetComplete <- struct{}{}
	}

	wrapper.createDNSRulesStreamCleaner(triggerFunc)
	wrapper.createDNSRulesReceiver(updateRules)
	close(dummyClient.closeCh) // recvs will fail
	select {
	case <-triggerCalled:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("Expected response to be sent to the response channel")
	}
}

// Test case 3: If client.Recv receives an error from server, the DNSRulesStreams is closed, and the connection trigger is called.
func TestDNSRulesStreamWrapper_ConnectionResetError(t *testing.T) {
	dummyClient := NewDummyDNSRulesClient()
	resetCalled := make(chan bool, 1)
	connectionWatcher := NewConnectionWatcher(
		nil,
		func() error {
			resetCalled <- true
			return nil
		},
		hivetest.Logger(t),
	)
	updateRules := func(rules *pb.DNSPolicyRules) {
		// This is a dummy function to satisfy the interface
		// In a real scenario, this would update the DNS rules
	}

	wrapper := &DNSRulesStreamWrapper{
		dnsRulesStreamLock:  utils.NewErrorAwareLock(nil),
		dnsRulesStream:      dummyClient,
		streamResetComplete: make(chan struct{}),
		connectionLock:      connectionWatcher.connectionLock,
		log:                 hivetest.Logger(t),
	}

	if connectionWatcher == nil {
		t.Fatalf("expected connectionWatcher to be non-nil")
	}

	triggerCalled := make(chan bool, 1)
	triggerFunc := func(reason string) {
		triggerCalled <- true
		wrapper.streamResetComplete <- struct{}{}
	}

	wrapper.createDNSRulesStreamCleaner(triggerFunc)
	wrapper.createDNSRulesReceiver(updateRules)
	close(dummyClient.errCh)

	<-resetCalled
	<-triggerCalled
}
