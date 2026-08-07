package ezca

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/uuid"
	"github.com/markeytos/ezca-go/internal/api"
	"github.com/markeytos/ezca-go/internal/client"
)

func armScope(c cloud.Configuration) (string, error) {
	if svc, ok := c.Services[cloud.ResourceManager]; ok && svc.Audience != "" {
		return strings.TrimRight(svc.Audience, "/") + "/.default", nil
	}
	switch c.ActiveDirectoryAuthorityHost {
	case "", cloud.AzurePublic.ActiveDirectoryAuthorityHost:
		return "https://management.core.windows.net/.default", nil
	case cloud.AzureGovernment.ActiveDirectoryAuthorityHost:
		return "https://management.core.usgovcloudapi.net/.default", nil
	default:
		return "", fmt.Errorf("ezca: cannot determine Azure Resource Manager scope for cloud with authority host %q; set Services[cloud.ResourceManager].Audience", c.ActiveDirectoryAuthorityHost)
	}
}

type Client struct {
	internal    client.Client
	ezcaBaseURL string
}

func (c *Client) ListAuthorities(ctx context.Context) ([]*Authority, error) {
	reqURL, err := url.JoinPath(c.ezcaBaseURL, "/api/CA/GetMyCAs")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, err
	}
	var ias []*api.Authority
	err = c.internal.DoWithTokenJSONDecodeResponseInAPIResult(ctx, req, &ias)
	if err != nil {
		return nil, err
	}

	cas := make([]*Authority, len(ias))
	for i, ia := range ias {
		cas[i], err = newFromInternalAuthority(ia)
		if err != nil {
			return nil, err
		}
	}

	return cas, err
}

func (c *Client) ListSSLAuthorities(ctx context.Context) ([]*SSLAuthority, error) {
	req, err := c.listAuthoritiesRequestFromAPI(ctx, "GetAvailableSSLCAs")
	if err != nil {
		return nil, err
	}
	var ats []*api.AuthorityTemplate
	err = c.internal.DoWithTokenJSONDecodeResponse(ctx, req, &ats)
	if err != nil {
		return nil, err
	}

	as, err := c.ListAuthorities(ctx)
	if err != nil {
		return nil, err
	}
	authMap := map[uuid.UUID]*Authority{}
	authIdx := 0

	sslCAs := make([]*SSLAuthority, len(ats))
	for i, at := range ats {
		if at.TemplateType != api.TemplateTypeSSL {
			return nil, errors.New("ezca: one of the authorities fetched was not of an SSL template")
		}

		auth, ok := authMap[at.ID]
		if !ok {
			for authIdx < len(as) {
				a := as[authIdx]
				authIdx++
				if a.ID == at.ID {
					auth = a
					break
				}
				authMap[a.ID] = a
			}
			if auth == nil {
				auth, err = c.sslTemplateInfo(ctx, at.ID, at.TemplateID)
				if err != nil {
					return nil, fmt.Errorf("failed getting SSL details: %v", err)
				}
			}
		}

		sslCAs[i] = &SSLAuthority{
			Authority:  auth,
			TemplateID: at.TemplateID,
		}
	}

	return sslCAs, err
}

func (c *Client) sslTemplateInfo(ctx context.Context, id, templateID uuid.UUID) (*Authority, error) {
	req, err := c.sslTemplateInfoRequest(ctx, id)
	if err != nil {
		return nil, err
	}

	ats := []*api.AuthorityTemplate{}
	err = c.internal.DoWithTokenJSONDecodeResponse(ctx, req, &ats)
	if err != nil {
		return nil, err
	}

	for _, at := range ats {
		if at.ID == id && at.TemplateID == templateID {
			return newFromInternalAuthority(at.Authority)
		}
	}
	return nil, fmt.Errorf("could not find SSL details: certificate with ID %s and template %s", id, templateID)
}

func (c *Client) sslTemplateInfoRequest(ctx context.Context, id uuid.UUID) (*http.Request, error) {
	req, err := c.newRequest(ctx, http.MethodGet, nil, "/api/CA/GetSSLCA")
	if err != nil {
		return nil, err
	}
	q := req.URL.Query()
	q.Add("caID", id.String())
	req.URL.RawQuery = q.Encode()
	return req, nil
}

func (c *Client) ListSCEPAuthorities(ctx context.Context) ([]*Authority, error) {
	return c.listAuthoritiesFromAPI(ctx, "GetAvailableScepCAs")
}

func (c *Client) ListIssuingAuthorities(ctx context.Context) ([]*Authority, error) {
	return c.listAuthoritiesFromAPI(ctx, "GetAvailableCertIssuingCAs")
}

func (c *Client) listAuthoritiesFromAPI(ctx context.Context, apiEndpoint string) ([]*Authority, error) {
	req, err := c.listAuthoritiesRequestFromAPI(ctx, apiEndpoint)
	if err != nil {
		return nil, err
	}
	var ias []*api.Authority
	err = c.internal.DoWithTokenJSONDecodeResponse(ctx, req, &ias)
	if err != nil {
		return nil, err
	}

	cas := make([]*Authority, len(ias))
	for i, ia := range ias {
		cas[i], err = newFromInternalAuthority(ia)
		if err != nil {
			return nil, err
		}
	}

	return cas, err
}

func (c Client) listAuthoritiesRequestFromAPI(ctx context.Context, api string) (*http.Request, error) {
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

// Option configures a Client created by NewClient.
type Option func(*clientOptions)

type clientOptions struct {
	cloud cloud.Configuration
}

// WithCloud selects the Azure sovereign cloud EZCA is reached in. The client
// requests a token whose scope is that cloud's Azure Resource Manager audience,
// so pass cloud.AzureGovernment for Azure Government. When unset, the Azure
// public cloud is used.
func WithCloud(c cloud.Configuration) Option {
	return func(o *clientOptions) { o.cloud = c }
}

// NewClient creates a new EZCA client. Pass the EZCA URL; it will be stripped
// where only scheme and domain remain. By default the client authenticates
// against the Azure public cloud; use WithCloud to target a sovereign cloud
// such as Azure Government.
func NewClient(ezcaURL string, credential azcore.TokenCredential, opts ...Option) (*Client, error) {
	baseURL, err := parseEZCABaseURL(ezcaURL)
	if err != nil {
		return nil, err
	}

	o := clientOptions{cloud: cloud.AzurePublic}
	for _, fn := range opts {
		fn(&o)
	}
	scope, err := armScope(o.cloud)
	if err != nil {
		return nil, err
	}

	c := &Client{
		internal: client.NewClient(credential, policy.TokenRequestOptions{
			Scopes: []string{scope},
		}),
		ezcaBaseURL: baseURL,
	}
	return c, nil
}

// parseEZCABaseURL strips an EZCA URL down to scheme and host, defaulting to
// https and requiring https.
func parseEZCABaseURL(ezcaURL string) (string, error) {
	// Need to parse twice since on first pass host is not set properly
	parsedURL, err := url.Parse(ezcaURL)
	if err != nil {
		return "", err
	}
	if parsedURL.Scheme == "" {
		parsedURL.Scheme = "https"
	} else if parsedURL.Scheme != "https" {
		return "", errors.New("ezca: instance must be reached with https")
	}
	if parsedURL.Host == "" {
		parsedURL, err = url.Parse(parsedURL.String())
		if err != nil {
			return "", err
		}
	}
	if parsedURL.Host == "" {
		return "", errors.New("ezca: instance URL must include a host, e.g. https://portal.ezca.io")
	}
	baseURL := url.URL{
		Scheme: parsedURL.Scheme,
		Host:   parsedURL.Host,
	}
	return baseURL.String(), nil
}
