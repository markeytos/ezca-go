package ezca

import (
	"net/http"
	"os"
	"testing"

	"github.com/google/uuid"
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
		},
		{
			ID:           uuid.Nil,
			FriendlyName: "Second",
		},
	}

	testSSLAuthorities = []*SSLAuthority{
		{
			Authority: &Authority{
				ID:           uuid.Nil,
				FriendlyName: "First",
			},
			Template: &Template{
				TemplateType: TemplateTypeSSL,
				TemplateID:   uuid.Max,
			},
		},
		{
			Authority: &Authority{
				ID:           uuid.Nil,
				FriendlyName: "Second",
			},
			Template: &Template{
				TemplateType: TemplateTypeSSL,
				TemplateID:   uuid.Max,
			},
		},
	}
	testSSLAuthoritiesBase []*AuthorityTemplate
)

func TestMain(m *testing.M) {
	testSSLAuthoritiesBase = make([]*AuthorityTemplate, len(testSSLAuthorities))
	for i, ssl := range testSSLAuthorities {
		testSSLAuthoritiesBase[i] = (*AuthorityTemplate)(ssl)
	}
	os.Exit(m.Run())
}

func TestListAuthorities(t *testing.T) {
	var url string
	c := &Client{
		internal: &testshared.MockClient{
			DoJSONDecodeResponseInAPIResultFunc: func(req *http.Request, res any) error {
				url = req.URL.String()
				a := res.(*[]*Authority)
				*a = make([]*Authority, len(testAuthorities))
				copy(*a, testAuthorities)
				return nil
			},
		},
		ezcaBaseURL: testURL,
	}
	authorities, err := c.ListAuthorities(t.Context())
	require.NoError(t, err)
	assert.Equal(t, authorities, testAuthorities)
	assert.Equal(t, url, "https://test.ezca.io/api/CA/GetMyCAs")
}

func TestListSSLAuthorities(t *testing.T) {
	var url string
	c := &Client{
		internal: &testshared.MockClient{
			DoJSONDecodeResponseFunc: func(req *http.Request, res any) error {
				url = req.URL.String()
				a := res.(*[]*AuthorityTemplate)
				*a = make([]*AuthorityTemplate, len(testSSLAuthoritiesBase))
				copy(*a, testSSLAuthoritiesBase)
				return nil
			},
		},
		ezcaBaseURL: testURL,
	}
	authorities, err := c.ListSSLAuthorities(t.Context())
	require.NoError(t, err)
	assert.Equal(t, authorities, testSSLAuthorities)
	assert.Equal(t, url, "https://test.ezca.io/api/CA/GetAvailableSSLCAs")
}

func TestListSCEPAuthorities(t *testing.T) {
	var url string
	c := &Client{
		internal: &testshared.MockClient{
			DoJSONDecodeResponseFunc: func(req *http.Request, res any) error {
				url = req.URL.String()
				a := res.(*[]*Authority)
				*a = make([]*Authority, len(testAuthorities))
				copy(*a, testAuthorities)
				return nil
			},
		},
		ezcaBaseURL: testURL,
	}
	authorities, err := c.ListSCEPAuthorities(t.Context())
	require.NoError(t, err)
	assert.Equal(t, authorities, testAuthorities)
	assert.Equal(t, url, "https://test.ezca.io/api/CA/GetAvailableScepCAs")
}

func TestListIssuingAuthorities(t *testing.T) {
	var url string
	c := &Client{
		internal: &testshared.MockClient{
			DoJSONDecodeResponseFunc: func(req *http.Request, res any) error {
				url = req.URL.String()
				a := res.(*[]*Authority)
				*a = make([]*Authority, len(testAuthorities))
				copy(*a, testAuthorities)
				return nil
			},
		},
		ezcaBaseURL: testURL,
	}
	authorities, err := c.ListIssuingAuthorities(t.Context())
	require.NoError(t, err)
	assert.Equal(t, authorities, testAuthorities)
	assert.Equal(t, url, "https://test.ezca.io/api/CA/GetAvailableCertIssuingCAs")
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
			assert.Equal(t, c, &Client{
				internal:    client.NewClient(&testshared.MockCredential{}, ezcaDefaultTokenRequestOptions),
				ezcaBaseURL: "https://portal.ezca.io",
			})
		})
	}

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
