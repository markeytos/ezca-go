package testshared

import (
	"context"
	"net/http"
)

type MockClient struct {
	DoFunc                              func(req *http.Request) (*http.Response, error)
	DoJSONDecodeResponseFunc            func(req *http.Request, res any) error
	DoResponseInAPIResultFunc           func(req *http.Request) (string, error)
	DoJSONDecodeResponseInAPIResultFunc func(req *http.Request, res any) error
}

func (c *MockClient) Do(req *http.Request) (*http.Response, error) {
	return c.DoFunc(req)
}

func (c *MockClient) DoJSONDecodeResponse(req *http.Request, res any) error {
	return c.DoJSONDecodeResponseFunc(req, res)
}

func (c *MockClient) DoResponseInAPIResult(req *http.Request) (string, error) {
	return c.DoResponseInAPIResultFunc(req)
}

func (c *MockClient) DoJSONDecodeResponseInAPIResult(req *http.Request, res any) error {
	return c.DoJSONDecodeResponseInAPIResultFunc(req, res)
}

func (c *MockClient) DoWithToken(ctx context.Context, req *http.Request) (*http.Response, error) {
	return c.DoFunc(req)
}

func (c *MockClient) DoWithTokenJSONDecodeResponse(ctx context.Context, req *http.Request, res any) error {
	return c.DoJSONDecodeResponseFunc(req, res)
}

func (c *MockClient) DoWithTokenResponseInAPIResult(ctx context.Context, req *http.Request) (string, error) {
	return c.DoResponseInAPIResultFunc(req)
}

func (c *MockClient) DoWithTokenJSONDecodeResponseInAPIResult(ctx context.Context, req *http.Request, res any) error {
	return c.DoJSONDecodeResponseInAPIResultFunc(req, res)
}
