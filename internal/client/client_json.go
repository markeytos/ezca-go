package client

import (
	"context"
	"encoding/json"
	"net/http"
)

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
