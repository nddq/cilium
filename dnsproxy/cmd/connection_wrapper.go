package cmd

import (
	"log/slog"

	"github.com/cilium/cilium/dnsproxy/utils"
	"github.com/cilium/cilium/pkg/logging/logfields"
)

type ConnectionWatcher struct {
	connectionLock          *utils.ErrorAwareLock
	connectionCloseFunction func() error
	log                     *slog.Logger
}

func NewConnectionWatcher(
	cancelUsers func(),
	connectionCloseFunction func() error, log *slog.Logger,
) *ConnectionWatcher {
	cw := &ConnectionWatcher{
		connectionLock:          utils.NewErrorAwareLock(cancelUsers),
		connectionCloseFunction: connectionCloseFunction,
		log:                     log,
	}
	cw.startConnectionResetGoRoutine()
	return cw
}

func (cw *ConnectionWatcher) UpdateCancelUsersFunction(cancelUsers func()) {
	cw.connectionLock.SetCancelUsers(cancelUsers)
}

func (cw *ConnectionWatcher) startConnectionResetGoRoutine() {
	go func() {
		for {
			cw.log.Debug("Connection wrapper waiting for connection error on lock", logfields.Value, cw.connectionLock)
			cw.connectionLock.GetLockIfResourceErrored()
			cw.log.Info("Connection wrapper woken up by error, closing the connection")
			// Reset the connection
			cw.connectionCloseFunction()
			// Mark the connection as error-free
			cw.connectionLock.MarkResourceAsErrorFree()
			cw.connectionLock.Unlock()
			cw.log.Info("Connection wrapper closed connection successfully")
		}
	}()
}
