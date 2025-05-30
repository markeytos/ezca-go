package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/markeytos/ezca-go/internal/clock"
)

type Client struct {
	Clock clock.Clock

	credential   azcore.TokenCredential
	tokenOptions policy.TokenRequestOptions
	token        azcore.AccessToken
}

func NewClient(credential azcore.TokenCredential, tokenOptions policy.TokenRequestOptions) *Client {
	return &Client{
		Clock:        clock.RealClock{},
		credential:   credential,
		tokenOptions: tokenOptions,
	}
}

func (c *Client) DoWithToken(ctx context.Context, req *http.Request) (*http.Response, error) {
	token, err := c.getToken(ctx)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Authorization", "Bearer "+token)
	return c.Do(req)
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	// TODO: add retry and reauth when token is expired (pipeline of sorts)
	return http.DefaultClient.Do(req)
}

func (c *Client) getToken(ctx context.Context) (string, error) {
	var err error
	if c.token == (azcore.AccessToken{}) {
		c.token, err = c.credential.GetToken(ctx, c.tokenOptions)
	}
	if c.token.ExpiresOn.Before(c.Clock.Now()) {
		c.token, err = c.credential.GetToken(ctx, c.tokenOptions)
	}
	if err != nil {
		return "", err
	}
	return c.token.Token, nil
}

func (c *Client) DoWithTokenJSONDecodeResponse(ctx context.Context, req *http.Request, res any) error {
	httpRes, err := c.DoWithToken(ctx, req)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(httpRes.Body)
	return dec.Decode(res)
}

func (c *Client) DoJSONDecodeResponse(req *http.Request, res any) error {
	httpRes, err := c.Do(req)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(httpRes.Body)
	return dec.Decode(res)
}

type apiResult struct {
	Success bool   `json:"Success"`
	Message string `json:"Message"`
}

func (c *Client) DoWithTokenJSONDecodeResponseInAPIResult(ctx context.Context, req *http.Request, res any) error {
	msg, err := c.DoWithTokenResponseInAPIResult(ctx, req)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(msg), res)
}

func (c *Client) DoWithTokenResponseInAPIResult(ctx context.Context, req *http.Request) (string, error) {
	result := apiResult{}

	err := c.DoWithTokenJSONDecodeResponse(ctx, req, &result)
	if err != nil {
		return "", err
	}

	if !result.Success {
		return "", fmt.Errorf("api error: %s", result.Message)
	}

	return result.Message, nil
}

func (c *Client) DoJSONDecodeResponseInAPIResult(req *http.Request, res any) error {
	msg, err := c.DoResponseInAPIResult(req)
	if err != nil {
		return err
	}
	return json.Unmarshal([]byte(msg), res)
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
