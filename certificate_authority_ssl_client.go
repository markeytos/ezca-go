package ezca

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"

	"github.com/google/uuid"
)

type SSLCertificateAuthorityClient struct {
	client *Client
	ca     *SSLCertificateAuthority
}

func NewSSLCertificateAuthorityClient(client *Client, ca *SSLCertificateAuthority) *SSLCertificateAuthorityClient {
	return &SSLCertificateAuthorityClient{
		client: client,
		ca:     ca,
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

type SignRequest struct {
	CertificateAuthorityID uuid.UUID `json:"CAID"`
	TemplateID             uuid.UUID `json:"TemplateID"`
	CertificateRequest     rawCSR    `json:"CSR"`
	Subject                string    `json:"SubjectName"`
	SubjectAltNames        []string  `json:"SubjectAltNames"` // TODO: fix this value
	ValidityInDays         int       `json:"ValidityInDays"`
	SelectedLocation       string    `json:"SelectedLocation"`
	ExtendedKeyUsages      []string  `json:"EKUs"`
	KeyUsages              []string  `json:"KeyUsages"`
}

type Certificate x509.Certificate

func (c *Certificate) UnmarshalJSON(jsonBytes []byte) error {
	var certpem string
	err := json.Unmarshal(jsonBytes, &certpem)
	if err != nil {
		return err
	}
	block, _ := pem.Decode([]byte(certpem))
	if block == nil || block.Type != "CERTIFICATE" {
		return errors.New("failed to decode PEM block or not a certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return err
	}
	*c = *(*Certificate)(cert)
	return nil
}

type SignResponse struct {
	NewCertificate *Certificate `json:"CertificatePEM,omitempty"`
	Issuing        *Certificate `json:"IssuingCACertificate,omitempty"`
	Root           *Certificate `json:"RootCertificate,omitempty"`
}

func (c *SSLCertificateAuthorityClient) Sign(ctx context.Context, csr []byte, subject string) ([]*x509.Certificate, error) {
	req, err := c.signRequest(ctx, csr, subject)
	if err != nil {
		return nil, err
	}

	res := SignResponse{}
	err = c.client.internal.DoWithTokenJSONDecodeResponse(ctx, req, &res)
	if err != nil {
		return nil, err
	}

	if res.NewCertificate == nil {
		return nil, errors.New("unexpected error certificate was not returned after signing")
	}
	if res.Issuing == nil {
		return nil, errors.New("unexpected error certificate issuer was not returned")
	}

	certs := make([]*x509.Certificate, 0, 3)
	certs = append(certs, (*x509.Certificate)(res.NewCertificate))
	certs = append(certs, (*x509.Certificate)(res.Issuing))
	if res.Root != nil {
		certs = append(certs, (*x509.Certificate)(res.Root))
	}
	return certs, nil
}

func (c *SSLCertificateAuthorityClient) signRequest(ctx context.Context, csr []byte, subject string) (*http.Request, error) {
	sr := &SignRequest{
		CertificateAuthorityID: c.ca.ID,
		TemplateID:             c.ca.TemplateID,
		CertificateRequest:     (rawCSR)(csr),
		Subject:                subject,
		SubjectAltNames:        []string{},
		ValidityInDays:         5,
		SelectedLocation:       "Generate Locally",
		ExtendedKeyUsages:      []string{"1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2"},
		KeyUsages:              []string{"Key Encipherment", "Digital Signature"},
	}
	return c.client.newRequestWithJSONBody(ctx, http.MethodPost, sr, "/api/CA/RequestSSLCertificateV2")
}
