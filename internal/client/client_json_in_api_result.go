package client

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

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
