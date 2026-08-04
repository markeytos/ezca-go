package ezca

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/google/uuid"
)

// ezcaJWTAudience is the audience EZCA expects on certificate-authentication
// JWTs. The server also accepts https://agent.keytos.io.
const ezcaJWTAudience = "https://ezca.io"

type httpDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// CertificateClient authenticates to EZCA using an existing certificate and its
// RSA private key (a certificate-signed JWT) rather than an Azure AD token. It
// is used for certificate lifecycle operations, such as renewal, where the
// caller proves possession of a certificate EZCA previously issued.
type CertificateClient struct {
	baseURL string
	http    httpDoer
	now     func() time.Time
}

// NewCertificateClient creates a client for certificate-authenticated EZCA
// operations. The EZCA URL is stripped down to scheme and host and must be
// reachable over https.
func NewCertificateClient(ezcaURL string) (*CertificateClient, error) {
	baseURL, err := parseEZCABaseURL(ezcaURL)
	if err != nil {
		return nil, err
	}
	return &CertificateClient{
		baseURL: baseURL,
		http:    http.DefaultClient,
		now:     time.Now,
	}, nil
}

// CertificateCreatedResponse is the certificate chain returned by EZCA issuance
// and renewal endpoints that return the full chain.
type CertificateCreatedResponse struct {
	Certificate *Certificate `json:"CertificatePEM"`
	IssuingCA   *Certificate `json:"IssuingCACertificate"`
	Root        *Certificate `json:"RootCertificate"`
}

type certRenewRequest struct {
	CSR            rawCSR `json:"CSR"`
	ValidityInDays int    `json:"ValidityInDays"`
}

type certAuthPayload struct {
	Certificate string           `json:"Certificate"`
	Payload     certRenewRequest `json:"Payload"`
}

// RenewCertificateV3 renews an existing EZCA-issued certificate. The cert and
// its RSA private key authenticate the request; csr is a DER-encoded PKCS#10
// request whose subject and SANs must match the existing certificate (EZCA
// re-derives them server side and rejects a mismatch). validityDays is the
// requested lifetime of the renewed certificate. On success it returns the new
// leaf certificate followed by the issuing CA and, when present, the root.
func (c *CertificateClient) RenewCertificateV3(
	ctx context.Context,
	cert *x509.Certificate,
	key *rsa.PrivateKey,
	csr []byte,
	validityDays int,
) ([]*x509.Certificate, error) {
	if cert == nil || key == nil {
		return nil, errors.New("ezca: certificate and private key are required for renewal")
	}
	if _, ok := cert.PublicKey.(*rsa.PublicKey); !ok {
		return nil, errors.New("ezca: only RSA certificates are supported for certificate based authentication")
	}
	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}
	if err := parsedCSR.CheckSignature(); err != nil {
		return nil, err
	}

	token, err := c.authToken(cert, key)
	if err != nil {
		return nil, err
	}

	payload := certAuthPayload{
		Certificate: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})),
		Payload: certRenewRequest{
			CSR:            rawCSR(parsedCSR.Raw),
			ValidityInDays: validityDays,
		},
	}
	// Marshal a pointer so the nested rawCSR field is addressable and its
	// PEM MarshalJSON is used (matching the signing request path).
	bodyBytes, err := json.Marshal(&payload)
	if err != nil {
		return nil, err
	}

	reqURL, err := url.JoinPath(c.baseURL, "/api/Certificates/RenewCertificateV3")
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)

	res, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	respBytes, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	if res.StatusCode < http.StatusOK || res.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("ezca: renewal failed with status %d: %s", res.StatusCode, strings.TrimSpace(string(respBytes)))
	}

	var ccr CertificateCreatedResponse
	if err := unmarshalMaybeWrapped(respBytes, &ccr); err != nil {
		return nil, fmt.Errorf("ezca: could not decode renewal response: %v", err)
	}
	leaf := asX509(ccr.Certificate)
	issuing := asX509(ccr.IssuingCA)
	if leaf == nil {
		return nil, errors.New("ezca: unexpected error certificate was not returned after renewal")
	}
	if issuing == nil {
		return nil, errors.New("ezca: unexpected error certificate issuer was not returned")
	}

	certs := make([]*x509.Certificate, 0, 3)
	certs = append(certs, leaf, issuing)
	if root := asX509(ccr.Root); root != nil {
		certs = append(certs, root)
	}
	return certs, nil
}

// asX509 returns the parsed certificate, or nil if the field was absent or an
// empty PEM string. Some EZCA responses include an empty RootCertificate, which
// unmarshals into a non-nil but zero-valued Certificate; treating it as present
// would emit an empty PEM block into the chain.
func asX509(c *Certificate) *x509.Certificate {
	if c == nil {
		return nil
	}
	x := (*x509.Certificate)(c)
	if len(x.Raw) == 0 {
		return nil
	}
	return x
}

// authToken builds the RS256 JWT that authenticates certificate-based EZCA
// requests. It mirrors the EZCA reference client: the header carries the SHA-1
// thumbprint in x5t, and the payload is scoped to the EZCA audience for 30
// minutes.
func (c *CertificateClient) authToken(cert *x509.Certificate, key *rsa.PrivateKey) (string, error) {
	now := c.now()
	thumb := sha1.Sum(cert.Raw)
	header := map[string]any{
		"alg": "RS256",
		"typ": "JWT",
		"x5t": strings.ToUpper(hex.EncodeToString(thumb[:])),
	}
	claims := map[string]any{
		"aud": ezcaJWTAudience,
		"jti": uuid.NewString(),
		"nbf": now.Unix(),
		"exp": now.Add(30 * time.Minute).Unix(),
	}
	return signRS256(header, claims, key)
}

// signRS256 produces a compact RS256 JWS from the given header and claims.
func signRS256(header, claims map[string]any, key *rsa.PrivateKey) (string, error) {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerBytes) + "." + enc.EncodeToString(claimsBytes)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", err
	}
	return signingInput + "." + enc.EncodeToString(signature), nil
}

// unmarshalMaybeWrapped decodes JSON that may be either a bare object or a JSON
// string containing that object; some EZCA endpoints return the body
// double-encoded.
func unmarshalMaybeWrapped(body []byte, v any) error {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) > 0 && trimmed[0] == '"' {
		var inner string
		if err := json.Unmarshal(trimmed, &inner); err != nil {
			return err
		}
		trimmed = []byte(inner)
	}
	return json.Unmarshal(trimmed, v)
}
