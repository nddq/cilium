package utils

import (
	"context"
	"sync"

	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

var log = logging.DefaultSlogLogger.With(logfields.LogSubsys, "resource-lock")

// ErrorAwareLock provides a mechanism to synchronize access to a shared resource
// while tracking its error state. If there is one or more errors, a manager
// go routine acquires an exclusive lock and corrects the error. As long as there
// are no errors, multiple users can access the resource concurrently. Since the
// users may be waiting in a blocking state, the manager go routine can use context
// cancellation to wake them up give up their locks, so that errors can be corrected.
type ErrorAwareLock struct {
	cvMutex        lock.Mutex
	resourceErrors []error
	resourceSafeCv *sync.Cond
	resourceMutex  lock.RWMutex
	cancelUsers    context.CancelFunc
}

// NewErrorAwareLock creates a new ErrorAwareLock instance. The cancelUsers function
// is used to cancel the context of users holding a read lock.
func NewErrorAwareLock(cancelUsers context.CancelFunc) *ErrorAwareLock {
	sl := &ErrorAwareLock{
		resourceErrors: nil,
		cancelUsers:    cancelUsers,
	}
	sl.resourceSafeCv = sync.NewCond(&sl.cvMutex)
	return sl
}

func (sl *ErrorAwareLock) SetCancelUsers(cancelUsers context.CancelFunc) {
	sl.cancelUsers = cancelUsers
}

// GetRLockIfResourceErrorFree acquires a read lock if there are no resource errors.
// If there are errors, it waits until the resource is marked as error-free.
func (sl *ErrorAwareLock) GetRLockIfResourceErrorFree() {
	sl.cvMutex.Lock()
	for sl.resourceErrors != nil {
		sl.resourceSafeCv.Wait()
	}
	sl.resourceMutex.RLock()
	sl.cvMutex.Unlock()
	log.Debug("Acquired read lock")
}

// RUnlock releases the read lock.
func (sl *ErrorAwareLock) RUnlock() {
	sl.resourceMutex.RUnlock()
}

// MarkResourceAsErrored marks the resource as errored. The broadcast signal is to
// notify the manager go routine that the resource is in an error state. The manager
// can then acquire a write lock to correct the error.
func (sl *ErrorAwareLock) MarkResourceAsErrored(err error) {
	sl.cvMutex.Lock()
	sl.resourceErrors = append(sl.resourceErrors, err)
	sl.resourceSafeCv.Broadcast()
	sl.cvMutex.Unlock()
}

// GetErrorsNonLocking returns the current resource errors without acquiring a lock.
// This is useful for the manager to check the current error state. It is expected that
// the manager will acquire a write lock before correcting the errors.
func (sl *ErrorAwareLock) GetErrorsNonLocking() []error {
	return sl.resourceErrors
}

// GetLockIfResourceErrored acquires a write lock if there are resource errors.
// If there are no errors, it waits until the resource is marked as errored. This function
// is typically used by a manager go routine to correct the errors. It cacncels the
// context of users holding a read lock, so as to unblock the manager.
func (sl *ErrorAwareLock) GetLockIfResourceErrored() {
	sl.cvMutex.Lock()
	for sl.resourceErrors == nil {
		sl.resourceSafeCv.Wait()
	}

	if sl.cancelUsers != nil {
		log.Debug("Cancelling existing users")
		sl.cancelUsers()
	} else {
		log.Debug("Cancel function is nil")
	}

	sl.resourceMutex.Lock()
	sl.cvMutex.Unlock()
	log.Debug("Acquired write lock")
}

// Unlock releases the write lock.
func (sl *ErrorAwareLock) Unlock() {
	sl.resourceMutex.Unlock()
}

// MarkResourceAsErrorFree marks the resource as error-free, likely after the
// manager go routine has corrected the errors. It broadcasts a signal
// to wake up all waiting users.
func (sl *ErrorAwareLock) MarkResourceAsErrorFree() {
	sl.cvMutex.Lock()
	sl.resourceErrors = nil
	sl.resourceSafeCv.Broadcast()
	sl.cvMutex.Unlock()
}
