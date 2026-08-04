package ezca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeDoer struct {
	fn func(*http.Request) (*http.Response, error)
}

func (f *fakeDoer) Do(req *http.Request) (*http.Response, error) { return f.fn(req) }

func newTestRSACert(t *testing.T, cn string, notBefore, notAfter time.Time) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		DNSNames:     []string{cn},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, key
}

func certPEM(c *x509.Certificate) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw}))
}

func newTestCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: []string{cn},
	}, key)
	require.NoError(t, err)
	return der
}

func TestRenewCertificateV3(t *testing.T) {
	now := time.Date(2026, 8, 4, 0, 0, 0, 0, time.UTC)
	oldCert, oldKey := newTestRSACert(t, "app.ezca.io", now.Add(-300*24*time.Hour), now.Add(65*24*time.Hour))
	newLeaf, _ := newTestRSACert(t, "app.ezca.io", now, now.Add(365*24*time.Hour))
	issuing, _ := newTestRSACert(t, "issuing.ezca.io", now, now.Add(3650*24*time.Hour))
	root, _ := newTestRSACert(t, "root.ezca.io", now, now.Add(3650*24*time.Hour))
	csrDER := newTestCSR(t, "app.ezca.io")

	respBody, err := json.Marshal(map[string]string{
		"CertificatePEM":       certPEM(newLeaf),
		"IssuingCACertificate": certPEM(issuing),
		"RootCertificate":      certPEM(root),
	})
	require.NoError(t, err)

	t.Run("full chain and request shape", func(t *testing.T) {
		var reqURL string
		var authHeader string
		var reqBody []byte
		doer := &fakeDoer{fn: func(req *http.Request) (*http.Response, error) {
			reqURL = req.URL.String()
			authHeader = req.Header.Get("Authorization")
			reqBody, _ = io.ReadAll(req.Body)
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(respBody)),
				Header:     make(http.Header),
			}, nil
		}}
		c := &CertificateClient{baseURL: "https://test.ezca.io", http: doer, now: func() time.Time { return now }}

		certs, err := c.RenewCertificateV3(context.Background(), oldCert, oldKey, csrDER, 365)
		require.NoError(t, err)
		require.Len(t, certs, 3)
		assert.Equal(t, newLeaf.Raw, certs[0].Raw)
		assert.Equal(t, issuing.Raw, certs[1].Raw)
		assert.Equal(t, root.Raw, certs[2].Raw)

		assert.Equal(t, "https://test.ezca.io/api/Certificates/RenewCertificateV3", reqURL)

		// Authorization header: RS256 JWT signed by the old key, x5t = old cert thumbprint.
		require.True(t, strings.HasPrefix(authHeader, "Bearer "))
		token := strings.TrimPrefix(authHeader, "Bearer ")
		parts := strings.Split(token, ".")
		require.Len(t, parts, 3)

		headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
		require.NoError(t, err)
		var header map[string]any
		require.NoError(t, json.Unmarshal(headerJSON, &header))
		assert.Equal(t, "RS256", header["alg"])
		assert.Equal(t, "JWT", header["typ"])
		thumb := sha1.Sum(oldCert.Raw)
		assert.Equal(t, strings.ToUpper(hex.EncodeToString(thumb[:])), header["x5t"])

		claimsJSON, err := base64.RawURLEncoding.DecodeString(parts[1])
		require.NoError(t, err)
		var claims map[string]any
		require.NoError(t, json.Unmarshal(claimsJSON, &claims))
		assert.Equal(t, "https://ezca.io", claims["aud"])
		assert.NotEmpty(t, claims["jti"])
		assert.Equal(t, float64(now.Unix()), claims["nbf"])
		assert.Equal(t, float64(now.Add(30*time.Minute).Unix()), claims["exp"])

		// Signature verifies against the old cert public key.
		sig, err := base64.RawURLEncoding.DecodeString(parts[2])
		require.NoError(t, err)
		digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
		require.NoError(t, rsa.VerifyPKCS1v15(&oldKey.PublicKey, crypto.SHA256, digest[:], sig))

		// Request body shape.
		var payload struct {
			Certificate string `json:"Certificate"`
			Payload     struct {
				CSR            string `json:"CSR"`
				ValidityInDays int    `json:"ValidityInDays"`
			} `json:"Payload"`
		}
		require.NoError(t, json.Unmarshal(reqBody, &payload))
		assert.Equal(t, 365, payload.Payload.ValidityInDays)
		assert.Contains(t, payload.Payload.CSR, "CERTIFICATE REQUEST")
		block, _ := pem.Decode([]byte(payload.Certificate))
		require.NotNil(t, block)
		assert.Equal(t, oldCert.Raw, block.Bytes)
	})

	t.Run("empty root certificate is dropped", func(t *testing.T) {
		body, err := json.Marshal(map[string]string{
			"CertificatePEM":       certPEM(newLeaf),
			"IssuingCACertificate": certPEM(issuing),
			"RootCertificate":      "",
		})
		require.NoError(t, err)
		doer := &fakeDoer{fn: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		}}
		c := &CertificateClient{baseURL: "https://test.ezca.io", http: doer, now: func() time.Time { return now }}
		certs, err := c.RenewCertificateV3(context.Background(), oldCert, oldKey, csrDER, 365)
		require.NoError(t, err)
		require.Len(t, certs, 2)
		assert.Equal(t, newLeaf.Raw, certs[0].Raw)
		assert.Equal(t, issuing.Raw, certs[1].Raw)
	})

	t.Run("string-wrapped response body", func(t *testing.T) {
		wrapped, err := json.Marshal(string(respBody))
		require.NoError(t, err)
		doer := &fakeDoer{fn: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(bytes.NewReader(wrapped)),
				Header:     make(http.Header),
			}, nil
		}}
		c := &CertificateClient{baseURL: "https://test.ezca.io", http: doer, now: func() time.Time { return now }}
		certs, err := c.RenewCertificateV3(context.Background(), oldCert, oldKey, csrDER, 365)
		require.NoError(t, err)
		require.Len(t, certs, 3)
		assert.Equal(t, newLeaf.Raw, certs[0].Raw)
	})

	t.Run("non-2xx status", func(t *testing.T) {
		doer := &fakeDoer{fn: func(_ *http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: http.StatusBadRequest,
				Body:       io.NopCloser(strings.NewReader("CSR does not match certificate")),
				Header:     make(http.Header),
			}, nil
		}}
		c := &CertificateClient{baseURL: "https://test.ezca.io", http: doer, now: func() time.Time { return now }}
		certs, err := c.RenewCertificateV3(context.Background(), oldCert, oldKey, csrDER, 365)
		assert.ErrorContains(t, err, "status 400")
		assert.Nil(t, certs)
	})

	t.Run("rejects non-RSA certificate", func(t *testing.T) {
		ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		tmpl := &x509.Certificate{
			SerialNumber: big.NewInt(2),
			Subject:      pkix.Name{CommonName: "ec.ezca.io"},
			NotBefore:    now,
			NotAfter:     now.Add(24 * time.Hour),
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &ecKey.PublicKey, ecKey)
		require.NoError(t, err)
		ecCert, err := x509.ParseCertificate(der)
		require.NoError(t, err)

		c := &CertificateClient{baseURL: "https://test.ezca.io", http: &fakeDoer{}, now: func() time.Time { return now }}
		_, err = c.RenewCertificateV3(context.Background(), ecCert, oldKey, csrDER, 365)
		assert.ErrorContains(t, err, "only RSA certificates are supported")
	})
}

func TestNewCertificateClient(t *testing.T) {
	t.Run("defaults scheme to https", func(t *testing.T) {
		c, err := NewCertificateClient("test.ezca.io")
		require.NoError(t, err)
		assert.Equal(t, "https://test.ezca.io", c.baseURL)
	})
	t.Run("rejects http", func(t *testing.T) {
		_, err := NewCertificateClient("http://test.ezca.io")
		assert.ErrorContains(t, err, "https")
	})
}
