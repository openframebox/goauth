package goauth

import (
	"fmt"
	"sync"
)

var (
	instance   *GoAuth
	instanceMu sync.RWMutex
)

// RegisterSingleton sets the current GoAuth as the package-wide instance.
// It overwrites any previously registered instance.
func (ga *GoAuth) RegisterSingleton() {
	instanceMu.Lock()
	instance = ga
	instanceMu.Unlock()
}

// RegisterSingletonOnce sets the singleton only if it hasn't been set yet.
// Returns an error if an instance is already registered and differs from ga.
func (ga *GoAuth) RegisterSingletonOnce() error {
	instanceMu.Lock()
	defer instanceMu.Unlock()
	if instance == nil {
		instance = ga
		return nil
	}
	if instance != ga {
		return fmt.Errorf("goauth singleton already registered")
	}
	return nil
}

// GetInstance returns the registered package-wide GoAuth instance, or nil
// if no instance has been registered.
func GetInstance() *GoAuth {
	instanceMu.RLock()
	defer instanceMu.RUnlock()
	return instance
}

// ReplaceSingletonForTest replaces the current singleton and returns a
// restore function that reverts to the previous instance. Intended for tests.
func ReplaceSingletonForTest(ga *GoAuth) (restore func()) {
	instanceMu.Lock()
	prev := instance
	instance = ga
	instanceMu.Unlock()
	return func() {
		instanceMu.Lock()
		instance = prev
		instanceMu.Unlock()
	}
}
