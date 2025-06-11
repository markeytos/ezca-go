package client

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/markeytos/ezca-go/internal/clock"
	"github.com/markeytos/ezca-go/internal/testshared"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testTimeLayout = "2006-01-02"

	testJSONStr = `
{
	"key": "value",
	"list": [0, 1, 2]
}
`
	testAPIResultSuccessStr = `{
	"Success": true,
	"Message": "contents"
}`
	testAPIResultSuccessWithJSONStr = `{
	"Success": true,
	"Message": "{\"key\": \"value\", \"list\": [0, 1, 2]}"
}`
	testAPIResultErrorStr = `{
	"Success": false,
	"Message": "api error msg"
}`
	testErrStr         = "Error: error msg"
	testInvalidJSONStr = `{
	"key": "value",
	"list": [0, 1, 2],
}`
)

var (
	timeEmpty   = timeMustParse("2020-01-01")
	timeRefresh = timeMustParse("2020-01-10")
	timeExpired = timeMustParse("2020-01-17")

	emptyToken = azcore.AccessToken{}
	testToken  = azcore.AccessToken{
		Token:     "token",
		ExpiresOn: timeMustParse("2020-01-14"),
	}
	testTokenWithRefresh = azcore.AccessToken{
		Token:     "token w refresh",
		ExpiresOn: timeMustParse("2020-01-14"),
		RefreshOn: timeMustParse("2020-01-07"),
	}
	testTokenNew = azcore.AccessToken{
		Token:     "token new",
		ExpiresOn: timeMustParse("2020-01-20"),
	}

	errNoCred          = errors.New("no credential")
	credentialNewToken = testshared.MockCredential{Token: testTokenNew}
	credentialNoToken  = testshared.MockCredential{Error: errNoCred}

	errBadClient = errors.New("bad client")
	badClient    = MockHttpClient{DoFunc: func(r *http.Request) (*http.Response, error) {
		return nil, errBadClient
	}}

	testTokenRequestOptions = policy.TokenRequestOptions{Scopes: []string{"test"}}
	testJSON                = jsonStruct{Key: "value", List: []int{0, 1, 2}}
)

type MockHttpClient struct {
	DoFunc func(*http.Request) (*http.Response, error)
}

func (c *MockHttpClient) Do(req *http.Request) (*http.Response, error) {
	return c.DoFunc(req)
}

type jsonStruct struct {
	Key  string `json:"key"`
	List []int  `json:"list"`
}

func TestNewClient(t *testing.T) {
	c := NewClient(&credentialNewToken, testTokenRequestOptions)
	require.NotNil(t, c)
	assert.Equal(t, &client{
		clock:        clock.RealClock{},
		client:       http.DefaultClient,
		credential:   &credentialNewToken,
		tokenOptions: testTokenRequestOptions,
	}, c)
}

func TestDoWithToken(t *testing.T) {
	for name, v := range map[string]*struct {
		ClockNow          time.Time
		CurrentCredential azcore.TokenCredential
		CurrentToken      azcore.AccessToken
	}{
		"valid credential empty": {
			ClockNow:          timeEmpty,
			CurrentCredential: &credentialNewToken,
			CurrentToken:      emptyToken,
		},
		"valid credential refresh": {
			ClockNow:          timeRefresh,
			CurrentCredential: &credentialNewToken,
			CurrentToken:      testTokenWithRefresh,
		},
		"valid credential expired": {
			ClockNow:          timeExpired,
			CurrentCredential: &credentialNewToken,
			CurrentToken:      testToken,
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := &http.Request{}
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: v.ClockNow},
				v.CurrentCredential,
				v.CurrentToken,
				req,
				"",
			)
			res, err := c.DoWithToken(t.Context(), testRequest())
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, http.Header{"Authorization": []string{"Bearer " + testTokenNew.Token}}, req.Header)
		})
	}

	t.Run("error in client", func(t *testing.T) {
		c := newClientWithMockHttp(
			testshared.MockClock{Time: timeEmpty},
			&credentialNewToken,
			emptyToken,
			&badClient,
		)
		res, err := c.DoWithToken(t.Context(), testRequest())
		require.ErrorIs(t, err, errBadClient)
		assert.Nil(t, res)
	})

	for name, token := range map[string]azcore.AccessToken{
		"invalid credential": emptyToken,
		"expired credential": testToken,
	} {
		t.Run(name, func(t *testing.T) {
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: timeExpired},
				&credentialNoToken,
				token,
				nil,
				"",
			)
			res, err := c.DoWithToken(t.Context(), nil)
			require.ErrorIs(t, err, errNoCred)
			assert.Nil(t, res)
		})
	}
}

func TestDoWithTokenJSONDecodeResponse(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		req := &http.Request{}
		s := jsonStruct{}
		c := newClientSaveReqWithBodyRes(
			testshared.MockClock{Time: timeEmpty},
			&credentialNewToken,
			emptyToken,
			req,
			testJSONStr,
		)
		err := c.DoWithTokenJSONDecodeResponse(t.Context(), testRequest(), &s)
		require.NoError(t, err)
		assert.Equal(t, testJSON, s)
		assert.Equal(t, http.Header{"Authorization": []string{"Bearer " + testTokenNew.Token}}, req.Header)
	})

	for name, v := range map[string]*struct {
		ResBodyStr string
		CompareStr string
	}{
		"error string": {
			ResBodyStr: testErrStr,
			CompareStr: "api error: error msg",
		},
		"invalid JSON": {
			ResBodyStr: testInvalidJSONStr,
			CompareStr: "invalid character '}'",
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := &http.Request{}
			s := jsonStruct{}
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: timeEmpty},
				&credentialNewToken,
				emptyToken,
				req,
				v.ResBodyStr,
			)
			err := c.DoWithTokenJSONDecodeResponse(t.Context(), testRequest(), &s)
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Equal(t, jsonStruct{}, s)
			assert.Equal(t, http.Header{"Authorization": []string{"Bearer " + testTokenNew.Token}}, req.Header)
		})
	}

	t.Run("error in client", func(t *testing.T) {
		s := jsonStruct{}
		c := newClientWithMockHttp(
			testshared.MockClock{Time: timeEmpty},
			&credentialNewToken,
			emptyToken,
			&badClient,
		)
		err := c.DoWithTokenJSONDecodeResponse(t.Context(), testRequest(), &s)
		require.ErrorIs(t, err, errBadClient)
		assert.Equal(t, jsonStruct{}, s)
	})

	for name, token := range map[string]azcore.AccessToken{
		"invalid credential": emptyToken,
		"expired credential": testToken,
	} {
		t.Run(name, func(t *testing.T) {
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: timeExpired},
				&credentialNoToken,
				token,
				nil,
				"",
			)
			err := c.DoWithTokenJSONDecodeResponse(t.Context(), nil, nil)
			require.ErrorIs(t, err, errNoCred)
		})
	}
}

func TestDoJSONDecodeResponse(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		s := jsonStruct{}
		c := newClientSaveReqWithBodyRes(
			testshared.MockClock{Time: timeEmpty},
			&credentialNewToken,
			testToken,
			nil,
			testJSONStr,
		)
		err := c.DoJSONDecodeResponse(nil, &s)
		require.NoError(t, err)
		assert.Equal(t, testJSON, s)
	})

	for name, v := range map[string]*struct {
		ResBodyStr string
		CompareStr string
	}{
		"error string": {
			ResBodyStr: testErrStr,
			CompareStr: "api error: error msg",
		},
		"invalid JSON": {
			ResBodyStr: testInvalidJSONStr,
			CompareStr: "invalid character '}'",
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := jsonStruct{}
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: timeEmpty},
				&credentialNewToken,
				emptyToken,
				nil,
				v.ResBodyStr,
			)
			err := c.DoJSONDecodeResponse(nil, &s)
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Equal(t, jsonStruct{}, s)
		})
	}

	t.Run("error in client", func(t *testing.T) {
		s := jsonStruct{}
		c := newClientWithMockHttp(
			testshared.MockClock{Time: timeEmpty},
			&credentialNoToken,
			testToken,
			&badClient,
		)
		err := c.DoJSONDecodeResponse(nil, &s)
		require.ErrorIs(t, err, errBadClient)
		assert.Equal(t, jsonStruct{}, s)
	})
}

func TestDoWithTokenJSONDecodeResponseInAPIResult(t *testing.T) {
	t.Run("successful result", func(t *testing.T) {
		req := &http.Request{}
		s := jsonStruct{}
		c := newClientSaveReqWithBodyRes(
			testshared.MockClock{Time: timeEmpty},
			&credentialNewToken,
			testToken,
			req,
			testAPIResultSuccessWithJSONStr,
		)
		err := c.DoWithTokenJSONDecodeResponseInAPIResult(t.Context(), testRequest(), &s)
		require.NoError(t, err)
		assert.Equal(t, testJSON, s)
		assert.Equal(t, http.Header{"Authorization": []string{"Bearer " + testToken.Token}}, req.Header)
	})

	for name, v := range map[string]*struct {
		ResBodyStr string
		CompareStr string
	}{
		"unsuccessful result": {
			ResBodyStr: testAPIResultErrorStr,
			CompareStr: "api error: api error msg",
		},
		"invalid JSON": {
			ResBodyStr: testInvalidJSONStr,
			CompareStr: "invalid character '}'",
		},
	} {
		t.Run(name, func(t *testing.T) {
			req := &http.Request{}
			s := jsonStruct{}
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: timeEmpty},
				&credentialNewToken,
				testToken,
				req,
				v.ResBodyStr,
			)
			err := c.DoWithTokenJSONDecodeResponseInAPIResult(t.Context(), testRequest(), &s)
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Equal(t, jsonStruct{}, s)
			assert.Equal(t, http.Header{"Authorization": []string{"Bearer " + testToken.Token}}, req.Header)
		})
	}

	t.Run("error in client", func(t *testing.T) {
		s := jsonStruct{}
		c := newClientWithMockHttp(
			testshared.MockClock{Time: timeEmpty},
			&credentialNewToken,
			emptyToken,
			&badClient,
		)
		err := c.DoWithTokenJSONDecodeResponseInAPIResult(t.Context(), testRequest(), &s)
		require.ErrorIs(t, err, errBadClient)
		assert.Equal(t, jsonStruct{}, s)
	})

	for name, token := range map[string]azcore.AccessToken{
		"invalid credential": emptyToken,
		"expired credential": testToken,
	} {
		t.Run(name, func(t *testing.T) {
			s := jsonStruct{}
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: timeExpired},
				&credentialNoToken,
				token,
				nil,
				"",
			)
			err := c.DoWithTokenJSONDecodeResponseInAPIResult(t.Context(), nil, &s)
			require.ErrorIs(t, err, errNoCred)
			assert.Equal(t, jsonStruct{}, s)
		})
	}
}

func TestDoWithTokenResponseInAPIResult(t *testing.T) {
	t.Run("successful result", func(t *testing.T) {
		req := &http.Request{}
		c := newClientSaveReqWithBodyRes(
			testshared.MockClock{Time: timeEmpty},
			&credentialNewToken,
			testToken,
			req,
			testAPIResultSuccessStr,
		)
		msg, err := c.DoWithTokenResponseInAPIResult(t.Context(), testRequest())
		require.NoError(t, err)
		require.Equal(t, "contents", msg)
		assert.Equal(t, http.Header{"Authorization": []string{"Bearer " + testToken.Token}}, req.Header)
	})

	for name, v := range map[string]*struct {
		ResBodyStr string
		CompareStr string
	}{
		"unsuccessful result": {
			ResBodyStr: testAPIResultErrorStr,
			CompareStr: "api error: api error msg",
		},
		"invalid JSON": {
			ResBodyStr: testInvalidJSONStr,
			CompareStr: "invalid character '}'",
		},
	} {
		req := &http.Request{}
		t.Run(name, func(t *testing.T) {
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: timeEmpty},
				&credentialNewToken,
				testToken,
				req,
				v.ResBodyStr,
			)
			msg, err := c.DoWithTokenResponseInAPIResult(t.Context(), testRequest())
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Empty(t, msg)
			assert.Equal(t, http.Header{"Authorization": []string{"Bearer " + testToken.Token}}, req.Header)
		})
	}

	t.Run("error in client", func(t *testing.T) {
		c := newClientWithMockHttp(
			testshared.MockClock{Time: timeEmpty},
			&credentialNewToken,
			emptyToken,
			&badClient,
		)
		res, err := c.DoWithTokenResponseInAPIResult(t.Context(), testRequest())
		require.ErrorIs(t, err, errBadClient)
		assert.Empty(t, res)
	})

	for name, token := range map[string]azcore.AccessToken{
		"invalid credential": emptyToken,
		"expired credential": testToken,
	} {
		t.Run(name, func(t *testing.T) {
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: timeExpired},
				&credentialNoToken,
				token,
				nil,
				"",
			)
			res, err := c.DoWithTokenResponseInAPIResult(t.Context(), nil)
			require.ErrorIs(t, err, errNoCred)
			assert.Empty(t, res)
		})
	}
}

func TestDoJSONDecodeResponseInAPIResult(t *testing.T) {
	t.Run("successful result", func(t *testing.T) {
		s := jsonStruct{}
		c := newClientSaveReqWithBodyRes(
			testshared.MockClock{Time: timeEmpty},
			&credentialNewToken,
			testToken,
			nil,
			testAPIResultSuccessWithJSONStr,
		)
		err := c.DoJSONDecodeResponseInAPIResult(nil, &s)
		require.NoError(t, err)
		assert.Equal(t, testJSON, s)
	})

	for name, v := range map[string]*struct {
		ResBodyStr string
		CompareStr string
	}{
		"unsuccessful result": {
			ResBodyStr: testAPIResultErrorStr,
			CompareStr: "api error: api error msg",
		},
		"invalid JSON": {
			ResBodyStr: testInvalidJSONStr,
			CompareStr: "invalid character '}'",
		},
	} {
		t.Run(name, func(t *testing.T) {
			s := jsonStruct{}
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: timeEmpty},
				&credentialNewToken,
				testToken,
				nil,
				v.ResBodyStr,
			)
			err := c.DoJSONDecodeResponseInAPIResult(nil, &s)
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Equal(t, jsonStruct{}, s)
		})
	}
}

func TestDoResponseInAPIResult(t *testing.T) {
	t.Run("successful result", func(t *testing.T) {
		c := newClientSaveReqWithBodyRes(
			testshared.MockClock{Time: timeEmpty},
			&credentialNewToken,
			testToken,
			nil,
			testAPIResultSuccessStr,
		)
		msg, err := c.DoResponseInAPIResult(nil)
		require.NoError(t, err)
		require.Equal(t, "contents", msg)
	})

	for name, v := range map[string]*struct {
		ResBodyStr string
		CompareStr string
	}{
		"unsuccessful result": {
			ResBodyStr: testAPIResultErrorStr,
			CompareStr: "api error: api error msg",
		},
		"invalid JSON": {
			ResBodyStr: testInvalidJSONStr,
			CompareStr: "invalid character '}'",
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newClientSaveReqWithBodyRes(
				testshared.MockClock{Time: timeEmpty},
				&credentialNewToken,
				testToken,
				nil,
				v.ResBodyStr,
			)
			msg, err := c.DoResponseInAPIResult(nil)
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Empty(t, msg)
		})
	}
}

func TestGetToken(t *testing.T) {
	for name, v := range map[string]*struct {
		ClockNow     time.Time
		CurrentToken azcore.AccessToken
	}{
		"valid credential empty": {
			ClockNow:     timeEmpty,
			CurrentToken: emptyToken,
		},
		"valid credential refresh": {
			ClockNow:     timeRefresh,
			CurrentToken: testTokenWithRefresh,
		},
		"valid credential expired": {
			ClockNow:     timeExpired,
			CurrentToken: testToken,
		},
	} {
		t.Run(name, func(t *testing.T) {
			c := newClient(
				testshared.MockClock{Time: v.ClockNow},
				&credentialNewToken,
				v.CurrentToken,
			)
			token, err := c.getToken(t.Context())
			require.NoError(t, err)
			assert.Equal(t, testTokenNew.Token, token)
		})
	}

	for name, token := range map[string]azcore.AccessToken{
		"invalid credential": emptyToken,
		"expired credential": testToken,
	} {
		t.Run(name, func(t *testing.T) {
			c := newClient(
				testshared.MockClock{Time: timeExpired},
				&credentialNoToken,
				token,
			)
			require.NotNil(t, c)
			token, err := c.getToken(t.Context())
			assert.Empty(t, token)
			require.ErrorIs(t, err, errNoCred)
		})
	}
}

func TestDecodeReaderJson(t *testing.T) {
	r := strings.NewReader(testJSONStr)
	s := jsonStruct{}
	err := decodeReaderJson(r, &s)
	require.NoError(t, err)
	assert.Equal(t, testJSON, s)
}

func TestDecodeDataJson(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		s := jsonStruct{}
		err := decodeDataJson([]byte(testJSONStr), &s)
		require.NoError(t, err)
		assert.Equal(t, testJSON, s)
	})

	t.Run("error string", func(t *testing.T) {
		s := jsonStruct{}
		err := decodeDataJson([]byte(testErrStr), &s)
		assert.ErrorContains(t, err, "api error: error msg")
		assert.Equal(t, jsonStruct{}, s)
	})

	t.Run("invalid JSON", func(t *testing.T) {
		s := jsonStruct{}
		err := decodeDataJson([]byte(testInvalidJSONStr), &s)
		assert.ErrorContains(t, err, "invalid character '}'")
		assert.Equal(t, jsonStruct{}, s)
	})
}

func newClientSaveReqWithBodyRes(clock testshared.MockClock, credential azcore.TokenCredential, token azcore.AccessToken, req *http.Request, body string) *client {
	return newClientWithMockHttp(
		clock,
		credential,
		token,
		&MockHttpClient{DoFunc: func(r *http.Request) (*http.Response, error) {
			if req != nil && r != nil {
				*req = *r
			}
			return &http.Response{
				Body: io.NopCloser(strings.NewReader(body)),
			}, nil
		}},
	)
}

func newClientWithMockHttp(clock testshared.MockClock, credential azcore.TokenCredential, token azcore.AccessToken, client httpClient) *client {
	c := newClient(clock, credential, token)
	c.client = client
	return c
}

func newClient(clock testshared.MockClock, credential azcore.TokenCredential, token azcore.AccessToken) *client {
	return &client{
		clock:        clock,
		client:       http.DefaultClient,
		credential:   credential,
		tokenOptions: testTokenRequestOptions,
		token:        token,
	}
}

func testRequest() *http.Request {
	req, err := http.NewRequest(http.MethodGet, "/test/path", nil)
	if err != nil {
		panic(err)
	}
	return req
}

func timeMustParse(value string) time.Time {
	t, err := time.Parse(testTimeLayout, value)
	if err != nil {
		panic(err)
	}
	return t
}
