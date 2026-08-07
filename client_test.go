package ezca

import (
	"net/http"
	"strings"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/cloud"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/google/uuid"
	"github.com/markeytos/ezca-go/internal/api"
	"github.com/markeytos/ezca-go/internal/client"
	"github.com/markeytos/ezca-go/internal/testshared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testURL = "https://test.ezca.io"

var (
	testAuthorities = []*Authority{
		{
			ID:           uuid.Nil,
			FriendlyName: "First",
			IsPublic:     true,
			IsRoot:       true,
		},
		{
			ID:           uuid.Max,
			FriendlyName: "Second",
			IsPublic:     false,
			IsRoot:       false,
		},
	}

	testSSLAuthorities = []*SSLAuthority{
		{
			Authority: &Authority{
				ID:           uuid.Nil,
				FriendlyName: "First",
				IsPublic:     true,
				IsRoot:       true,
			},
			TemplateID: uuid.Max,
		},
		{
			Authority: &Authority{
				ID:           uuid.Max,
				FriendlyName: "Second",
				IsPublic:     false,
				IsRoot:       false,
			},
			TemplateID: uuid.Nil,
		},
	}

	testInternalAuthorities = []*api.Authority{
		{
			ID:           uuid.Nil,
			FriendlyName: "First",
			Type:         api.CATypePublic,
			Tier:         api.CATierRoot,
		},
		{
			ID:           uuid.Max,
			FriendlyName: "Second",
			Type:         api.CATypePrivate,
			Tier:         api.CATierSubordinate,
		},
	}

	testInternalAuthorityTemplate = []*api.AuthorityTemplate{
		{
			Authority: &api.Authority{
				ID:           uuid.Nil,
				FriendlyName: "First",
			},
			TemplateID:   uuid.Max,
			TemplateType: api.TemplateTypeSSL,
		},
		{
			Authority: &api.Authority{
				ID:           uuid.Max,
				FriendlyName: "Second",
			},
			TemplateID:   uuid.Nil,
			TemplateType: api.TemplateTypeSSL,
		},
	}
)

func TestListAuthorities(t *testing.T) {
	var url string
	c := &Client{
		internal: &testshared.MockClient{
			DoJSONDecodeResponseInAPIResultFunc: copyInternalAuthority(&url),
		},
		ezcaBaseURL: testURL,
	}
	authorities, err := c.ListAuthorities(t.Context())
	require.NoError(t, err)
	assert.Equal(t, testAuthorities, authorities)
	assert.Equal(t, "https://test.ezca.io/api/CA/GetMyCAs", url)
}

func TestListSSLAuthorities(t *testing.T) {
	t.Run("simple list", func(t *testing.T) {
		var urlA, urlB string
		c := &Client{
			internal: &testshared.MockClient{
				DoJSONDecodeResponseFunc: func(req *http.Request, res any) error {
					urlA = req.URL.String()
					a := res.(*[]*api.AuthorityTemplate)
					*a = make([]*api.AuthorityTemplate, len(testInternalAuthorityTemplate))
					copy(*a, testInternalAuthorityTemplate)
					return nil
				},
				DoJSONDecodeResponseInAPIResultFunc: copyInternalAuthority(&urlB),
			},
			ezcaBaseURL: testURL,
		}
		authorities, err := c.ListSSLAuthorities(t.Context())
		require.NoError(t, err)
		assert.Equal(t, testSSLAuthorities, authorities)
		assert.Equal(t, "https://test.ezca.io/api/CA/GetAvailableSSLCAs", urlA)
		assert.Equal(t, "https://test.ezca.io/api/CA/GetMyCAs", urlB)
	})

	t.Run("out of subscription list", func(t *testing.T) {
		var checkUUID uuid.UUID
		var urlA, urlB, urlC string
		c := &Client{
			internal: &testshared.MockClient{
				DoJSONDecodeResponseFunc: func(req *http.Request, res any) error {
					path := req.URL.Path

					if strings.Contains(path, "GetAvailableSSLCAs") {
						urlA = req.URL.String()
						a := res.(*[]*api.AuthorityTemplate)
						*a = make([]*api.AuthorityTemplate, 3)
						copy(*a, []*api.AuthorityTemplate{
							{
								Authority: &api.Authority{
									ID:           uuid.Nil,
									FriendlyName: "First",
								},
								TemplateID:   uuid.Max,
								TemplateType: api.TemplateTypeSSL,
							},
							{
								Authority: &api.Authority{
									ID:           uuid.Max,
									FriendlyName: "Second",
								},
								TemplateID:   uuid.Nil,
								TemplateType: api.TemplateTypeSSL,
							},
							{
								Authority: &api.Authority{
									ID:           uuid.Max,
									FriendlyName: "Third",
								},
								TemplateID:   uuid.Max,
								TemplateType: api.TemplateTypeSSL,
							},
						})
					} else if strings.Contains(path, "GetSSLCA") {
						urlB = req.URL.String()
						checkUUID, _ = uuid.Parse(req.URL.Query().Get("caID"))
						a := res.(*[]*api.AuthorityTemplate)
						*a = make([]*api.AuthorityTemplate, 1)
						copy(*a, []*api.AuthorityTemplate{
							{
								Authority: &api.Authority{
									ID:           uuid.Max,
									FriendlyName: "Third",
									Type:         api.CATypePrivate,
									Tier:         api.CATierRoot,
								},
								TemplateID:   uuid.Max,
								TemplateType: api.TemplateTypeSSL,
							},
						})
					} else {
						t.Errorf("unexpected url: %s", req.URL.String())
					}

					return nil
				},
				DoJSONDecodeResponseInAPIResultFunc: copyInternalAuthority(&urlC),
			},
			ezcaBaseURL: testURL,
		}
		authorities, err := c.ListSSLAuthorities(t.Context())
		require.NoError(t, err)
		assert.Equal(t, []*SSLAuthority{
			{
				Authority: &Authority{
					ID:           uuid.Nil,
					FriendlyName: "First",
					IsPublic:     true,
					IsRoot:       true,
				},
				TemplateID: uuid.Max,
			},
			{
				Authority: &Authority{
					ID:           uuid.Max,
					FriendlyName: "Second",
					IsPublic:     false,
					IsRoot:       false,
				},
				TemplateID: uuid.Nil,
			},
			{
				Authority: &Authority{
					ID:           uuid.Max,
					FriendlyName: "Third",
					IsPublic:     false,
					IsRoot:       true,
				},
				TemplateID: uuid.Max,
			},
		}, authorities)
		assert.Equal(t, uuid.Max, checkUUID)
		assert.Equal(t, "https://test.ezca.io/api/CA/GetAvailableSSLCAs", urlA)
		assert.Equal(t, "https://test.ezca.io/api/CA/GetSSLCA?caID=ffffffff-ffff-ffff-ffff-ffffffffffff", urlB)
		assert.Equal(t, "https://test.ezca.io/api/CA/GetMyCAs", urlC)
	})
}

func TestListSCEPAuthorities(t *testing.T) {
	var url string
	c := &Client{
		internal: &testshared.MockClient{
			DoJSONDecodeResponseFunc: copyInternalAuthority(&url),
		},
		ezcaBaseURL: testURL,
	}
	authorities, err := c.ListSCEPAuthorities(t.Context())
	require.NoError(t, err)
	assert.Equal(t, testAuthorities, authorities)
	assert.Equal(t, "https://test.ezca.io/api/CA/GetAvailableScepCAs", url)
}

func TestListIssuingAuthorities(t *testing.T) {
	var url string
	c := &Client{
		internal: &testshared.MockClient{
			DoJSONDecodeResponseFunc: copyInternalAuthority(&url),
		},
		ezcaBaseURL: testURL,
	}
	authorities, err := c.ListIssuingAuthorities(t.Context())
	require.NoError(t, err)
	assert.Equal(t, testAuthorities, authorities)
	assert.Equal(t, "https://test.ezca.io/api/CA/GetAvailableCertIssuingCAs", url)
}

func TestNewClient(t *testing.T) {
	for name, url := range map[string]string{
		"add https remove path": "portal.ezca.io/random/path",
		"add https":             "portal.ezca.io",
		"remove path":           "https://portal.ezca.io/random/path",
		"remove query":          "https://portal.ezca.io?key=value",
		"remove path and query": "https://portal.ezca.io/random/path?key=value",
	} {
		t.Run(name, func(t *testing.T) {
			c, err := NewClient(url, &testshared.MockCredential{})
			assert.NoError(t, err)
			assert.Equal(t, &Client{
				internal: client.NewClient(&testshared.MockCredential{}, policy.TokenRequestOptions{
					Scopes: []string{"https://management.core.windows.net/.default"},
				}),
				ezcaBaseURL: "https://portal.ezca.io",
			}, c)
		})
	}

	t.Run("government cloud uses the government ARM scope", func(t *testing.T) {
		c, err := NewClient("https://portal.ezca.io", &testshared.MockCredential{}, WithCloud(cloud.AzureGovernment))
		assert.NoError(t, err)
		assert.Equal(t, &Client{
			internal: client.NewClient(&testshared.MockCredential{}, policy.TokenRequestOptions{
				Scopes: []string{"https://management.core.usgovcloudapi.net/.default"},
			}),
			ezcaBaseURL: "https://portal.ezca.io",
		}, c)
	})

	for name, v := range map[string]*struct {
		url        string
		compareStr string
	}{
		"http url": {
			url:        "http://portal.ezca.io",
			compareStr: "instance must be reached with https",
		},
		"space": {
			url:        "https://portal ezca.io",
			compareStr: "invalid character \" \"",
		},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := NewClient(v.url, &testshared.MockCredential{})
			assert.ErrorContains(t, err, v.compareStr)
			assert.Nil(t, c)
		})
	}
}

func TestARMScope(t *testing.T) {
	for name, v := range map[string]struct {
		cloud cloud.Configuration
		want  string
	}{
		"public":                        {cloud.AzurePublic, "https://management.core.windows.net/.default"},
		"government":                    {cloud.AzureGovernment, "https://management.core.usgovcloudapi.net/.default"},
		"zero value defaults to public": {cloud.Configuration{}, "https://management.core.windows.net/.default"},
		"explicit resource manager audience wins": {
			cloud.Configuration{
				ActiveDirectoryAuthorityHost: "https://login.example.com/",
				Services: map[cloud.ServiceName]cloud.ServiceConfiguration{
					cloud.ResourceManager: {Audience: "https://management.example.com/"},
				},
			},
			"https://management.example.com/.default",
		},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := armScope(v.cloud)
			assert.NoError(t, err)
			assert.Equal(t, v.want, got)
		})
	}

	t.Run("unknown cloud without a resource manager audience errors", func(t *testing.T) {
		_, err := armScope(cloud.Configuration{ActiveDirectoryAuthorityHost: "https://login.example.com/"})
		assert.ErrorContains(t, err, "cannot determine Azure Resource Manager scope")
	})

	// Azure China is not a supported cloud: its built-in config carries no
	// Resource Manager audience, so it falls through to the error.
	t.Run("china is unsupported", func(t *testing.T) {
		_, err := armScope(cloud.AzureChina)
		assert.ErrorContains(t, err, "cannot determine Azure Resource Manager scope")
	})
}

func copyInternalAuthority(url *string) func(req *http.Request, res any) error {
	return func(req *http.Request, res any) error {
		*url = req.URL.String()
		a := res.(*[]*api.Authority)
		*a = make([]*api.Authority, len(testInternalAuthorities))
		copy(*a, testInternalAuthorities)
		return nil
	}
}
