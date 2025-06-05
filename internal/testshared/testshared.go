package testshared

import (
	"context"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
)

type MockCredential struct {
	Token azcore.AccessToken
	Error error
}

func (m *MockCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return m.Token, m.Error
}

type MockClock struct {
	Time time.Time
}

func (c MockClock) Now() time.Time {
	return c.Time
}

func (c MockClock) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

func (c MockClock) Tick(d time.Duration) <-chan time.Time {
	return time.Tick(d)
}
