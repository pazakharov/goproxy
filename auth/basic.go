package auth

import (
	"context"
	"strings"
	"sync"
)

// BasicAuth implements local file/argument based authentication
type BasicAuth struct {
	data sync.Map // username -> password
}

// NewBasicAuth creates a new BasicAuth instance
func NewBasicAuth() *BasicAuth {
	return &BasicAuth{}
}

// AddFromFile loads users from a file (format: "username:password" per line)
func (ba *BasicAuth) AddFromFile(file string) (n int, err error) {
	// This will be implemented to read from file
	// For now, stub - will integrate with existing ioutil.ReadFile logic
	return 0, nil
}

// Add adds users from string slice (format: "username:password")
func (ba *BasicAuth) Add(userpassArr []string) (n int) {
	for _, userpass := range userpassArr {
		u := strings.Split(userpass, ":")
		if len(u) == 2 {
			ba.data.Store(u[0], u[1])
			n++
		}
	}
	return
}

// Check validates a "username:password" string
func (ba *BasicAuth) Check(userpass string) (ok bool) {
	u := strings.Split(strings.TrimSpace(userpass), ":")
	if len(u) == 2 {
		if p, loaded := ba.data.Load(u[0]); loaded {
			return p.(string) == u[1]
		}
	}
	return false
}

// Total returns the number of registered users
func (ba *BasicAuth) Total() int {
	count := 0
	ba.data.Range(func(_, _ interface{}) bool {
		count++
		return true
	})
	return count
}

// Authenticate implements the Authenticator interface
func (ba *BasicAuth) Authenticate(ctx context.Context, creds Credentials) (Result, error) {
	userpass := creds.User + ":" + creds.Pass
	if ba.Check(userpass) {
		return Result{
			OK:   true,
			User: creds.User,
		}, nil
	}
	return Result{OK: false}, nil
}

// Close implements the Authenticator interface
func (ba *BasicAuth) Close() error {
	return nil
}
