package ezca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/markeytos/ezca-go/internal/client"
)

var (
	ezcaDefaultTokenRequestOptions = policy.TokenRequestOptions{
		Scopes: []string{"https://management.core.windows.net/.default"},
	}
)

type Client struct {
	internal    *client.Client
	ezcaBaseURL string
}

// Create a new EZCA client. Pass the EZCA URL, it will be stripped where only scheme and domain remain
func NewClient(ezcaURL string, credential azcore.TokenCredential) (*Client, error) {
	parsedURL, err := url.Parse(ezcaURL)
	if err != nil {
		return nil, err
	}
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	} else if parsedURL.Scheme != "https" {
		return nil, errors.New("EZCA must be reached with https")
	}

	baseURL := url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
	}

	c := &Client{
		internal:    client.NewClient(credential, ezcaDefaultTokenRequestOptions),
		ezcaBaseURL: baseURL.String(),
	}
	return c, nil
}

func (c *Client) ListCertificateAuthorities(ctx context.Context) ([]*CertificateAuthority, error) {
	reqURL, err := url.JoinPath(c.ezcaBaseURL, "/api/CA/GetMyCAs")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	var cas []*CertificateAuthority
	err = c.internal.DoWithTokenJSONDecodeResponseInAPIResult(ctx, req, &cas)
	return cas, err
}

func (c *Client) ListSSLCertificateAuthorities(ctx context.Context) ([]*SSLCertificateAuthority, error) {
	req, err := c.listCertificateAuthoritiesRequestFromAPI(ctx, "GetAvailableSSLCAs")
	if err != nil {
		return nil, err
	}
	var cats []*CertificateAuthorityTemplate
	err = c.internal.DoWithTokenJSONDecodeResponse(ctx, req, &cats)

	sslCAs := make([]*SSLCertificateAuthority, len(cats))

	for i, cat := range cats {
		if cat.TemplateType != TemplateTypeSSL {
			return nil, errors.New("one of the CAs returned was not of template type SSL")
		}
		sslCAs[i] = (*SSLCertificateAuthority)(cat)
	}

	return sslCAs, err
}

func (c *Client) ListSCEPCertificateAuthorities(ctx context.Context) ([]*CertificateAuthority, error) {
	return c.listCertificateAuthoritiesFromAPI(ctx, "GetAvailableScepCAs")
}

func (c *Client) ListIssuingCertificateAuthorities(ctx context.Context) ([]*CertificateAuthority, error) {
	return c.listCertificateAuthoritiesFromAPI(ctx, "GetAvailableCertIssuingCAs")
}

func (c *Client) listCertificateAuthoritiesFromAPI(ctx context.Context, api string) ([]*CertificateAuthority, error) {
	req, err := c.listCertificateAuthoritiesRequestFromAPI(ctx, api)
	if err != nil {
		return nil, err
	}
	var cas []*CertificateAuthority
	err = c.internal.DoWithTokenJSONDecodeResponse(ctx, req, &cas)
	return cas, err
}

func (c Client) listCertificateAuthoritiesRequestFromAPI(ctx context.Context, api string) (*http.Request, error) {
	return c.newRequest(ctx, http.MethodGet, nil, "/api/CA", api)
}

func (c Client) newRequestWithJSONBody(ctx context.Context, method string, body any, api ...string) (*http.Request, error) {
	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := c.newRequest(ctx, method, bytes.NewBuffer(bodyBytes), api...)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	return req, nil
}

func (c Client) newRequest(ctx context.Context, method string, body io.Reader, api ...string) (*http.Request, error) {
	reqURL, err := url.JoinPath(c.ezcaBaseURL, api...)
	if err != nil {
		return nil, err
	}
	return http.NewRequestWithContext(ctx, method, reqURL, body)
}
