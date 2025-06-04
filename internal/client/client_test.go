package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/markeytos/ezca-go/internal/clock"
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
	credentialNewToken = MockCredential{Token: testTokenNew}
	credentialNoToken  = MockCredential{Error: errNoCred}

	errBadClient = errors.New("bad client")
	badClient    = MockHttpClient{DoFunc: func(r *http.Request) (*http.Response, error) {
		return nil, errBadClient
	}}

	testTokenRequestOptions = policy.TokenRequestOptions{Scopes: []string{"test"}}
	testJSON                = jsonStruct{Key: "value", List: []int{0, 1, 2}}
)

type MockCredential struct {
	Token azcore.AccessToken
	Error error
}

func (m *MockCredential) GetToken(ctx context.Context, options policy.TokenRequestOptions) (azcore.AccessToken, error) {
	return m.Token, m.Error
}

type MockClock struct {
	now time.Time
}

func (c MockClock) Now() time.Time {
	return c.now
}

func (c MockClock) After(d time.Duration) <-chan time.Time {
	return time.After(d)
}

func (c MockClock) Tick(d time.Duration) <-chan time.Time {
	return time.Tick(d)
}

type MockHttpClient struct {
	DoFunc func(*http.Request) (*http.Response, error)
}

func (c *MockHttpClient) Do(req *http.Request) (*http.Response, error) {
	return c.DoFunc(req)
}

// type testVals struct {
// 	ClockNow          time.Time
// 	CurrentCredential azcore.TokenCredential
// 	CurrentToken      azcore.AccessToken
// 	ResBodyStr        string
// 	CompareStr        string
// }

type jsonStruct struct {
	Key  string `json:"key"`
	List []int  `json:"list"`
}

func TestNewClient(t *testing.T) {
	c := NewClient(&credentialNewToken, testTokenRequestOptions)
	require.NotNil(t, c)
	assert.Equal(t, c, &Client{
		clock:        clock.RealClock{},
		client:       http.DefaultClient,
		credential:   &credentialNewToken,
		tokenOptions: testTokenRequestOptions,
	})
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
				MockClock{now: v.ClockNow},
				v.CurrentCredential,
				v.CurrentToken,
				req,
				"",
			)
			res, err := c.DoWithToken(t.Context(), testRequest())
			require.NoError(t, err)
			require.NotNil(t, res)
			assert.Equal(t, req.Header["Authorization"], []string{"Bearer " + testTokenNew.Token})
		})
	}

	t.Run("error in client", func(t *testing.T) {
		c := newClientWithMockHttp(
			MockClock{now: timeEmpty},
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
				MockClock{now: timeExpired},
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
			MockClock{now: timeEmpty},
			&credentialNewToken,
			emptyToken,
			req,
			testJSONStr,
		)
		err := c.DoWithTokenJSONDecodeResponse(t.Context(), testRequest(), &s)
		require.NoError(t, err)
		assert.Equal(t, s, testJSON)
		assert.Equal(t, req.Header["Authorization"], []string{"Bearer " + testTokenNew.Token})
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
				MockClock{now: timeEmpty},
				&credentialNewToken,
				emptyToken,
				req,
				v.ResBodyStr,
			)
			err := c.DoWithTokenJSONDecodeResponse(t.Context(), testRequest(), &s)
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Equal(t, s, jsonStruct{})
			assert.Equal(t, req.Header["Authorization"], []string{"Bearer " + testTokenNew.Token})
		})
	}

	t.Run("error in client", func(t *testing.T) {
		s := jsonStruct{}
		c := newClientWithMockHttp(
			MockClock{now: timeEmpty},
			&credentialNewToken,
			emptyToken,
			&badClient,
		)
		err := c.DoWithTokenJSONDecodeResponse(t.Context(), testRequest(), &s)
		require.ErrorIs(t, err, errBadClient)
		assert.Equal(t, s, jsonStruct{})
	})

	for name, token := range map[string]azcore.AccessToken{
		"invalid credential": emptyToken,
		"expired credential": testToken,
	} {
		t.Run(name, func(t *testing.T) {
			c := newClientSaveReqWithBodyRes(
				MockClock{now: timeExpired},
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
			MockClock{now: timeEmpty},
			&credentialNewToken,
			testToken,
			nil,
			testJSONStr,
		)
		err := c.DoJSONDecodeResponse(nil, &s)
		require.NoError(t, err)
		assert.Equal(t, s, testJSON)
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
				MockClock{now: timeEmpty},
				&credentialNewToken,
				emptyToken,
				nil,
				v.ResBodyStr,
			)
			err := c.DoJSONDecodeResponse(nil, &s)
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Equal(t, s, jsonStruct{})
		})
	}

	t.Run("error in client", func(t *testing.T) {
		s := jsonStruct{}
		c := newClientWithMockHttp(
			MockClock{now: timeEmpty},
			&credentialNoToken,
			testToken,
			&badClient,
		)
		err := c.DoJSONDecodeResponse(nil, &s)
		require.ErrorIs(t, err, errBadClient)
		assert.Equal(t, s, jsonStruct{})
	})
}

func TestDoWithTokenJSONDecodeResponseInAPIResult(t *testing.T) {
	t.Run("successful result", func(t *testing.T) {
		req := &http.Request{}
		s := jsonStruct{}
		c := newClientSaveReqWithBodyRes(
			MockClock{now: timeEmpty},
			&credentialNewToken,
			testToken,
			req,
			testAPIResultSuccessWithJSONStr,
		)
		err := c.DoWithTokenJSONDecodeResponseInAPIResult(t.Context(), testRequest(), &s)
		require.NoError(t, err)
		assert.Equal(t, s, testJSON)
		assert.Equal(t, req.Header["Authorization"], []string{"Bearer " + testToken.Token})
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
				MockClock{now: timeEmpty},
				&credentialNewToken,
				testToken,
				req,
				v.ResBodyStr,
			)
			err := c.DoWithTokenJSONDecodeResponseInAPIResult(t.Context(), testRequest(), &s)
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Equal(t, s, jsonStruct{})
			assert.Equal(t, req.Header["Authorization"], []string{"Bearer " + testToken.Token})
		})
	}

	t.Run("error in client", func(t *testing.T) {
		s := jsonStruct{}
		c := newClientWithMockHttp(
			MockClock{now: timeEmpty},
			&credentialNewToken,
			emptyToken,
			&badClient,
		)
		err := c.DoWithTokenJSONDecodeResponseInAPIResult(t.Context(), testRequest(), &s)
		require.ErrorIs(t, err, errBadClient)
		assert.Equal(t, s, jsonStruct{})
	})

	for name, token := range map[string]azcore.AccessToken{
		"invalid credential": emptyToken,
		"expired credential": testToken,
	} {
		t.Run(name, func(t *testing.T) {
			s := jsonStruct{}
			c := newClientSaveReqWithBodyRes(
				MockClock{now: timeExpired},
				&credentialNoToken,
				token,
				nil,
				"",
			)
			err := c.DoWithTokenJSONDecodeResponseInAPIResult(t.Context(), nil, &s)
			require.ErrorIs(t, err, errNoCred)
			assert.Equal(t, s, jsonStruct{})
		})
	}
}

func TestDoWithTokenResponseInAPIResult(t *testing.T) {
	t.Run("successful result", func(t *testing.T) {
		req := &http.Request{}
		c := newClientSaveReqWithBodyRes(
			MockClock{now: timeEmpty},
			&credentialNewToken,
			testToken,
			req,
			testAPIResultSuccessStr,
		)
		msg, err := c.DoWithTokenResponseInAPIResult(t.Context(), testRequest())
		require.NoError(t, err)
		require.Equal(t, msg, "contents")
		assert.Equal(t, req.Header["Authorization"], []string{"Bearer " + testToken.Token})
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
				MockClock{now: timeEmpty},
				&credentialNewToken,
				testToken,
				req,
				v.ResBodyStr,
			)
			msg, err := c.DoWithTokenResponseInAPIResult(t.Context(), testRequest())
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Empty(t, msg)
			assert.Equal(t, req.Header["Authorization"], []string{"Bearer " + testToken.Token})
		})
	}

	t.Run("error in client", func(t *testing.T) {
		c := newClientWithMockHttp(
			MockClock{now: timeEmpty},
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
				MockClock{now: timeExpired},
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
			MockClock{now: timeEmpty},
			&credentialNewToken,
			testToken,
			nil,
			testAPIResultSuccessWithJSONStr,
		)
		err := c.DoJSONDecodeResponseInAPIResult(nil, &s)
		require.NoError(t, err)
		assert.Equal(t, s, testJSON)
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
				MockClock{now: timeEmpty},
				&credentialNewToken,
				testToken,
				nil,
				v.ResBodyStr,
			)
			err := c.DoJSONDecodeResponseInAPIResult(nil, &s)
			assert.ErrorContains(t, err, v.CompareStr)
			assert.Equal(t, s, jsonStruct{})
		})
	}
}

func TestDoResponseInAPIResult(t *testing.T) {
	t.Run("successful result", func(t *testing.T) {
		c := newClientSaveReqWithBodyRes(
			MockClock{now: timeEmpty},
			&credentialNewToken,
			testToken,
			nil,
			testAPIResultSuccessStr,
		)
		msg, err := c.DoResponseInAPIResult(nil)
		require.NoError(t, err)
		require.Equal(t, msg, "contents")
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
				MockClock{now: timeEmpty},
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
				MockClock{now: v.ClockNow},
				&credentialNewToken,
				v.CurrentToken,
			)
			token, err := c.getToken(t.Context())
			require.NoError(t, err)
			assert.Equal(t, token, testTokenNew.Token)
		})
	}

	for name, token := range map[string]azcore.AccessToken{
		"invalid credential": emptyToken,
		"expired credential": testToken,
	} {
		t.Run(name, func(t *testing.T) {
			c := newClient(
				MockClock{now: timeExpired},
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
	assert.Equal(t, s, testJSON)
}

func TestDecodeDataJson(t *testing.T) {
	t.Run("valid JSON", func(t *testing.T) {
		s := jsonStruct{}
		err := decodeDataJson([]byte(testJSONStr), &s)
		require.NoError(t, err)
		assert.Equal(t, s, testJSON)
	})

	t.Run("error string", func(t *testing.T) {
		s := jsonStruct{}
		err := decodeDataJson([]byte(testErrStr), &s)
		assert.ErrorContains(t, err, "api error: error msg")
		assert.Equal(t, s, jsonStruct{})
	})

	t.Run("invalid JSON", func(t *testing.T) {
		s := jsonStruct{}
		err := decodeDataJson([]byte(testInvalidJSONStr), &s)
		assert.ErrorContains(t, err, "invalid character '}'")
		assert.Equal(t, s, jsonStruct{})
	})
}

func newClientSaveReqWithBodyRes(clock MockClock, credential azcore.TokenCredential, token azcore.AccessToken, req *http.Request, body string) *Client {
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

func newClientWithMockHttp(clock MockClock, credential azcore.TokenCredential, token azcore.AccessToken, client httpClient) *Client {
	c := newClient(clock, credential, token)
	c.client = client
	return c
}

func newClient(clock MockClock, credential azcore.TokenCredential, token azcore.AccessToken) *Client {
	c := NewClient(credential, testTokenRequestOptions)
	c.clock = clock
	c.token = token
	return c
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
