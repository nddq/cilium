package utils

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
)

func TestRLock(t *testing.T) {
	// Test: Stream is initially safe, concurrent read locks can be acquired
	streamLock := NewErrorAwareLock(nil)
	streamLock.GetRLockIfResourceErrorFree()
	streamLock.GetRLockIfResourceErrorFree()
	streamLock.RUnlock()
	streamLock.GetRLockIfResourceErrorFree()
	streamLock.RUnlock()
	streamLock.RUnlock()
}

func TestMarkResourceAsUnsafe(t *testing.T) {
	// Test: Mark stream as unsafe - needs to be marked as safe again before read locks can be acquired
	var streamMarkedSafe atomic.Bool
	streamMarkedSafe.Store(false)
	streamLock := NewErrorAwareLock(nil)
	streamLock.MarkResourceAsErrored(errors.New("stream error"))
	go func() {
		streamMarkedSafe.Store(true)
		streamLock.MarkResourceAsErrorFree()
	}()

	// Test: GetRLockIfStreamSafe blocks until stream is marked safe
	streamLock.GetRLockIfResourceErrorFree()
	if !streamMarkedSafe.Load() {
		t.Fatalf("expected stream to be marked safe, got false")
	}
	streamLock.RUnlock()
}

func TestLock(t *testing.T) {
	// Test: Error correction by manager. Only one manager can acquire the lock at a time.
	var currentWriterCount atomic.Int32
	currentWriterCount.Store(0)
	var multipleWriters atomic.Bool
	multipleWriters.Store(false)
	var errorsRecorded atomic.Bool
	errorsRecorded.Store(true)
	streamLock := NewErrorAwareLock(nil)
	streamLock.MarkResourceAsErrored(errors.New("stream error"))
	var wg sync.WaitGroup
	wg.Add(2)

	for i := 0; i < 2; i++ {
		go func() {
			streamLock.GetLockIfResourceErrored()
			currentWriterCount.Add(1)
			if currentWriterCount.Load() != 1 {
				multipleWriters.Store(true)
			}

			if streamLock.GetErrorsNonLocking() == nil {
				errorsRecorded.Store(false)
			}

			// Make Stream Safe
			streamLock.MarkResourceAsErrorFree()
			currentWriterCount.Add(-1)
			streamLock.Unlock()
			wg.Done()
		}()
	}

	streamLock.GetRLockIfResourceErrorFree()
	streamLock.MarkResourceAsErrored(errors.New("stream error"))
	streamLock.RUnlock()
	wg.Wait()

	if multipleWriters.Load() {
		t.Fatalf("expected only one writer to acquire the lock, got multiple")
	}

	if !errorsRecorded.Load() {
		t.Fatalf("expected errors to be recorded, got none")
	}
}

func TestReadCancel(t *testing.T) {
	// Manager can cancel the context of users holding a read lock
	ctx, cancel := context.WithCancel(context.Background())
	streamLock := NewErrorAwareLock(cancel)
	go func() {
		streamLock.GetRLockIfResourceErrorFree()
		defer streamLock.RUnlock()
		streamLock.MarkResourceAsErrored(errors.New("stream error"))
		// wait to be cancelled
		<-ctx.Done()
	}()

	streamLock.GetLockIfResourceErrored()
	streamLock.Unlock()
}
