// TODO: add retry and reauth when token is expired (pipeline of sorts)

package client

import (
	"context"
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
