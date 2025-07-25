package ezca

import (
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"time"
	"unicode"

	"github.com/google/uuid"
)

type SignOptions struct {
	// Location source of the certificate. Defaults to "EZCA Go SDK" if not provided.
	SourceTag string

	Duration          time.Duration // Certificate validity duration. Defaults to 90 days if not set.
	KeyUsages         []KeyUsage    // Certificate key usages. Defaults to key encipherment and digital signature.
	ExtendedKeyUsages []ExtKeyUsage // Certificate extended key usages. Defaults to server authentication and client authentication.
	SubjectName       string        // Overwrite the subject name for the final certificate

	EmailAddresses []string   // Additional Subject Alternate Name Email Address (1)
	DNSNames       []string   // Additional Subject Alternate Name DNS Name (2)
	URIs           []*url.URL // Additional Subject Alternate Name URI (6)
	IPAddresses    []net.IP   // Additional Subject Alternate Name IP (7)
}

type SSLAuthorityClient struct {
	Authority *SSLAuthority
	client    *Client
	info      *SSLAuthorityInfo
}

type SSLAuthorityInfo struct {
	*SSLAuthority

	// TODO: fill this out
	// SubjectName     string
	// IssuerAuthority string
}

func (i *SSLAuthorityInfo) Clone() *SSLAuthorityInfo {
	return &SSLAuthorityInfo{
		SSLAuthority: &SSLAuthority{
			Authority: &Authority{
				ID:            i.ID,
				FriendlyName:  i.FriendlyName,
				KeyType:       i.KeyType,
				HashAlgorithm: i.HashAlgorithm,
				IsPublic:      i.IsPublic,
				IsRoot:        i.IsRoot,
			},
			TemplateID: i.TemplateID,
		},
	}
}

type rawCSR []byte

func (k *rawCSR) MarshalJSON() ([]byte, error) {
	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: *k,
	})
	return json.Marshal(string(csrPEM))
}

func (k *rawCSR) UnmarshalJSON(jsonBytes []byte) error {
	var csrpem string
	err := json.Unmarshal(jsonBytes, &csrpem)
	if err != nil {
		return err
	}
	b, _ := pem.Decode([]byte(csrpem))
	if b == nil {
		return errors.New("invalid PEM certificate request")
	}
	if b.Type != "CERTIFICATE REQUEST" {
		return errors.New("certificate request parsed is not a certificate request")
	}
	array := (*[]byte)(k)
	*array = make([]byte, len(b.Bytes))
	copy(*array, b.Bytes)
	return nil
}

type KeyUsage string

const (
	KeyUsageDigitalSignature KeyUsage = "Digital Signature"
	KeyUsageKeyEncipherment  KeyUsage = "Key Encipherment"
	KeyUsageDataEncipherment KeyUsage = "Data Encipherment"
	KeyUsageKeyAgreement     KeyUsage = "Key Agreement"
	KeyUsageNonRepudiation   KeyUsage = "Non Repudiation"
)

type ExtKeyUsage string

const (
	ExtKeyUsageAny                            ExtKeyUsage = "2.5.29.37.0"
	ExtKeyUsageServerAuth                     ExtKeyUsage = "1.3.6.1.5.5.7.3.1"
	ExtKeyUsageClientAuth                     ExtKeyUsage = "1.3.6.1.5.5.7.3.2"
	ExtKeyUsageCodeSigning                    ExtKeyUsage = "1.3.6.1.5.5.7.3.3"
	ExtKeyUsageEmailProtection                ExtKeyUsage = "1.3.6.1.5.5.7.3.4"
	ExtKeyUsageIPSECEndSystem                 ExtKeyUsage = "1.3.6.1.5.5.7.3.5"
	ExtKeyUsageIPSECTunnel                    ExtKeyUsage = "1.3.6.1.5.5.7.3.6"
	ExtKeyUsageIPSECUser                      ExtKeyUsage = "1.3.6.1.5.5.7.3.7"
	ExtKeyUsageTimeStamping                   ExtKeyUsage = "1.3.6.1.5.5.7.3.8"
	ExtKeyUsageOCSPSigning                    ExtKeyUsage = "1.3.6.1.5.5.7.3.9"
	ExtKeyUsageMicrosoftServerGatedCrypto     ExtKeyUsage = "1.3.6.1.4.1.311.10.3.3"
	ExtKeyUsageNetscapeServerGatedCrypto      ExtKeyUsage = "2.16.840.1.113730.4.1"
	ExtKeyUsageMicrosoftCommercialCodeSigning ExtKeyUsage = "1.3.6.1.4.1.311.2.1.22"
	ExtKeyUsageMicrosoftKernelCodeSigning     ExtKeyUsage = "1.3.6.1.4.1.311.61.1.1"
)

type Certificate x509.Certificate

func (c *Certificate) UnmarshalJSON(jsonBytes []byte) error {
	var certpem string
	err := json.Unmarshal(jsonBytes, &certpem)
	if err != nil {
		return err
	}
	if len(certpem) == 0 {
		return nil
	}
	block, _ := pem.Decode([]byte(certpem))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("ezca: failed to decode PEM block or not a certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	*c = *(*Certificate)(cert)
	return nil
}

func (c *SSLAuthorityClient) Info(ctx context.Context) (*SSLAuthorityInfo, error) {
	if c.info == nil ||
		c.info.ID != c.Authority.ID ||
		c.info.TemplateID != c.Authority.TemplateID {
		info, err := c.client.sslTemplateInfo(ctx, c.Authority.ID, c.Authority.TemplateID)
		if err != nil {
			return nil, err
		}

		c.Authority.FriendlyName = info.FriendlyName
		c.Authority.KeyType = info.KeyType
		c.Authority.HashAlgorithm = info.HashAlgorithm
		c.Authority.IsPublic = info.IsPublic
		c.Authority.IsRoot = info.IsRoot

		c.info = &SSLAuthorityInfo{
			SSLAuthority: &SSLAuthority{
				Authority: &Authority{
					ID:            c.Authority.ID,
					FriendlyName:  c.Authority.FriendlyName,
					KeyType:       c.Authority.KeyType,
					HashAlgorithm: c.Authority.HashAlgorithm,
					IsPublic:      c.Authority.IsPublic,
					IsRoot:        c.Authority.IsRoot,
				},
				TemplateID: c.Authority.TemplateID,
			},
		}
	}

	return c.info.Clone(), nil
}

type signResponse struct {
	NewCertificate *Certificate `json:"CertificatePEM,omitempty"`
	Issuing        *Certificate `json:"IssuingCACertificate,omitempty"`
	Root           *Certificate `json:"RootCertificate,omitempty"`
}

func (c *SSLAuthorityClient) Sign(ctx context.Context, csr []byte, opts *SignOptions) ([]*x509.Certificate, error) {
	req, err := c.signRequest(ctx, csr, opts)
	if err != nil {
		return nil, err
	}

	res := signResponse{}
	err = c.client.internal.DoWithTokenJSONDecodeResponse(ctx, req, &res)
	if err != nil {
		return nil, err
	}

	if res.NewCertificate == nil {
		return nil, errors.New("ezca: unexpected error certificate was not returned after signing")
	}
	if res.Issuing == nil {
		return nil, errors.New("ezca: unexpected error certificate issuer was not returned")
	}

	certs := make([]*x509.Certificate, 0, 3)
	certs = append(certs, (*x509.Certificate)(res.NewCertificate))
	certs = append(certs, (*x509.Certificate)(res.Issuing))
	if res.Root != nil {
		certs = append(certs, (*x509.Certificate)(res.Root))
	}
	return certs, nil
}

type signRequest struct {
	AuthorityID           uuid.UUID     `json:"CAID"`
	TemplateID            uuid.UUID     `json:"TemplateID"`
	CertificateRequest    rawCSR        `json:"CSR"`
	SubjectName           string        `json:"SubjectName"`
	SubjectAlternateNames []*san        `json:"SubjectAltNames"`
	ValidityInDays        int           `json:"ValidityInDays"`
	SelectedLocation      string        `json:"SelectedLocation"`
	KeyUsages             []KeyUsage    `json:"KeyUsages"`
	ExtendedKeyUsages     []ExtKeyUsage `json:"EKUs"`
}

func (c *SSLAuthorityClient) signRequest(ctx context.Context, csr []byte, opts *SignOptions) (*http.Request, error) {
	parsedCSR, err := x509.ParseCertificateRequest(csr)
	if err != nil {
		return nil, err
	}
	err = parsedCSR.CheckSignature()
	if err != nil {
		return nil, err
	}

	sr := &signRequest{
		AuthorityID:        c.Authority.ID,
		TemplateID:         c.Authority.TemplateID,
		CertificateRequest: rawCSR(parsedCSR.Raw),
		SubjectName:        parsedCSR.Subject.String(),
		ValidityInDays:     90,
		SelectedLocation:   "EZCA Go SDK",
		KeyUsages:          []KeyUsage{KeyUsageKeyEncipherment, KeyUsageDigitalSignature},
		ExtendedKeyUsages:  []ExtKeyUsage{ExtKeyUsageServerAuth, ExtKeyUsageClientAuth},
	}

	if opts != nil {
		if opts.SourceTag != "" {
			sr.SelectedLocation = opts.SourceTag
		}
		if opts.Duration != 0 {
			// NOTE: new API should be able to handle any duration
			days := int(math.Round(opts.Duration.Hours() / 24))
			if days == 0 {
				return nil, errors.New("ezca: duration must be in scale of days (> 24h)")
			} else if days < 0 {
				return nil, errors.New("ezca: duration must positive")
			}
			sr.ValidityInDays = days
		}
		if len(opts.KeyUsages) > 0 {
			sr.KeyUsages = opts.KeyUsages
		}
		if len(opts.ExtendedKeyUsages) > 0 {
			sr.ExtendedKeyUsages = opts.ExtendedKeyUsages
		}
		if opts.SubjectName != "" {
			sr.SubjectName = opts.SubjectName
		}
		additionalSANs, err := marshalSANs(opts.DNSNames, opts.EmailAddresses, opts.IPAddresses, opts.URIs)
		if err != nil {
			return nil, err
		}
		sr.SubjectAlternateNames = append(sr.SubjectAlternateNames, additionalSANs...)
	}

	return c.client.newRequestWithJSONBody(ctx, http.MethodPost, sr, "/api/CA/RequestSSLCertificateV2")
}

func (c *SSLAuthorityClient) Revoke(ctx context.Context, cert *x509.Certificate) error {
	thumb := sha1.Sum(cert.Raw)
	return c.RevokeWithThumbprint(ctx, thumb)
}

func (c *SSLAuthorityClient) RevokeWithThumbprint(ctx context.Context, thumbprint [20]byte) error {
	req, err := c.revokeRequest(ctx, thumbprint)
	if err != nil {
		return err
	}
	_, err = c.client.internal.DoWithTokenResponseInAPIResult(ctx, req)
	return err
}

func (c *SSLAuthorityClient) revokeRequest(ctx context.Context, thumbprint [20]byte) (*http.Request, error) {
	return c.client.newRequestWithJSONBody(ctx, http.MethodPost,
		&struct {
			AuthorityID uuid.UUID `json:"CAID"`
			TemplateID  uuid.UUID `json:"TemplateID"`
			Thumbprint  string    `json:"Thumbprint"`
		}{
			AuthorityID: c.Authority.ID,
			TemplateID:  c.Authority.TemplateID,
			Thumbprint:  hex.EncodeToString(thumbprint[:]),
		},
		"/api/CA/RevokeCertificateV2")
}

func NewSSLAuthorityClient(ctx context.Context, client *Client, id, templateID uuid.UUID) (*SSLAuthorityClient, error) {
	if client == nil {
		return nil, errors.New("ezca: cannot create an authority with a nil client")
	}

	c := &SSLAuthorityClient{
		Authority: &SSLAuthority{
			Authority: &Authority{
				ID: id,
			},
			TemplateID: templateID,
		},
		client: client,
	}
	_, err := c.Info(ctx)
	if err != nil {
		return nil, err
	}

	return c, nil
}

type nameType int

const (
	nameTypeEmail nameType = 1
	nameTypeDNS   nameType = 2
	nameTypeURI   nameType = 6
	nameTypeIP    nameType = 7
)

type san struct {
	NameType nameType `json:"SubjectAltType"`
	Value    string   `json:"ValueSTR"`
}

func marshalSANs(dnsNames, emailAddresses []string, ipAddresses []net.IP, uris []*url.URL) ([]*san, error) {
	sans := make([]*san, 0, len(dnsNames)+len(emailAddresses)+len(ipAddresses)+len(uris))
	for _, name := range dnsNames {
		if err := isASCII(name); err != nil {
			return nil, err
		}
		sans = append(sans, &san{
			NameType: nameTypeDNS,
			Value:    name,
		})
	}
	for _, email := range emailAddresses {
		if err := isASCII(email); err != nil {
			return nil, err
		}
		sans = append(sans, &san{
			NameType: nameTypeEmail,
			Value:    email,
		})
	}
	for _, rawIP := range ipAddresses {
		// If possible, we always want to encode IPv4 addresses in 4 bytes.
		ip := rawIP.To4()
		if ip == nil {
			ip = rawIP
		}
		sans = append(sans, &san{
			NameType: nameTypeIP,
			Value:    ip.String(),
		})
	}
	for _, uri := range uris {
		uriStr := uri.String()
		if err := isASCII(uriStr); err != nil {
			return nil, err
		}
		sans = append(sans, &san{
			NameType: nameTypeURI,
			Value:    uriStr,
		})
	}
	return sans, nil
}

func isASCII(s string) error {
	for _, r := range s {
		if r > unicode.MaxASCII {
			return fmt.Errorf("ezca: %q cannot be encoded as an ASCII string", s)
		}
	}
	return nil
}
