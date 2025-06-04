package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/markeytos/ezca-go/internal/clock"
)

type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
}

type Client struct {
	clock  clock.Clock
	client httpClient

	credential   azcore.TokenCredential
	tokenOptions policy.TokenRequestOptions
	token        azcore.AccessToken
}

func NewClient(credential azcore.TokenCredential, tokenOptions policy.TokenRequestOptions) *Client {
	return &Client{
		clock:        clock.RealClock{},
		client:       http.DefaultClient,
		credential:   credential,
		tokenOptions: tokenOptions,
	}
}

func (c *Client) DoWithToken(ctx context.Context, req *http.Request) (*http.Response, error) {
	err := c.attachToken(ctx, req)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// TODO: add retry and reauth when token is expired (pipeline of sorts)
	// https://github.com/markeytos/ezca-go/issues/3
	return c.client.Do(req)
}

func (c *Client) DoWithTokenJSONDecodeResponse(ctx context.Context, req *http.Request, res any) error {
	err := c.attachToken(ctx, req)
	if err != nil {
		return err
	}
	return c.DoJSONDecodeResponse(req, res)
}

func (c *Client) DoJSONDecodeResponse(req *http.Request, res any) error {
	httpRes, err := c.Do(req)
	if err != nil {
		return err
	}
	return decodeReaderJson(httpRes.Body, res)
}

type apiResult struct {
	Success bool   `json:"Success"`
	Message string `json:"Message"`
}

func (c *Client) DoWithTokenJSONDecodeResponseInAPIResult(ctx context.Context, req *http.Request, res any) error {
	err := c.attachToken(ctx, req)
	if err != nil {
		return err
	}
	return c.DoJSONDecodeResponseInAPIResult(req, res)
}

func (c *Client) DoWithTokenResponseInAPIResult(ctx context.Context, req *http.Request) (string, error) {
	err := c.attachToken(ctx, req)
	if err != nil {
		return "", err
	}
	return c.DoResponseInAPIResult(req)
}

func (c *Client) DoJSONDecodeResponseInAPIResult(req *http.Request, res any) error {
	msg, err := c.DoResponseInAPIResult(req)
	if err != nil {
		return err
	}
	return decodeDataJson([]byte(msg), res)
}

func (c *Client) DoResponseInAPIResult(req *http.Request) (string, error) {
	result := apiResult{}

	err := c.DoJSONDecodeResponse(req, &result)
	if err != nil {
		return "", err
	}

	if !result.Success {
		return "", fmt.Errorf("api error: %s", result.Message)
	}
	return result.Message, nil
}

func (c *Client) attachToken(ctx context.Context, req *http.Request) error {
	token, err := c.getToken(ctx)
	if err != nil {
		return err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	return nil
}

func (c *Client) getToken(ctx context.Context) (string, error) {
	var err error
	if c.token == (azcore.AccessToken{}) {
		c.token, err = c.credential.GetToken(ctx, c.tokenOptions)
	} else if !c.token.RefreshOn.IsZero() && c.token.RefreshOn.Before(c.clock.Now()) {
		c.token, err = c.credential.GetToken(ctx, c.tokenOptions)
	} else if c.token.ExpiresOn.Before(c.clock.Now()) {
		c.token, err = c.credential.GetToken(ctx, c.tokenOptions)
	}
	if err != nil {
		return "", err
	}
	return c.token.Token, nil
}

func decodeReaderJson(r io.Reader, v any) error {
	data, err := io.ReadAll(r)
	if err != nil {
		return fmt.Errorf("could not get data: %v", err)
	}
	return decodeDataJson(data, v)
}

func decodeDataJson(data []byte, v any) error {
	err := json.Unmarshal(data, v)
	if err == nil {
		return nil
	}
	if strings.HasPrefix(string(data), "Error:") {
		return errors.New(strings.Replace(string(data), "Error:", "api error:", 1))
	}
	return fmt.Errorf("invalid response from server: %v", err)
}
