package ezca

import "github.com/google/uuid"

type SSLCertificateAuthority CertificateAuthorityTemplate

func NewSSLCertificateAuthority(caid, templateID uuid.UUID) *SSLCertificateAuthority {
	return &SSLCertificateAuthority{
		CertificateAuthority: &CertificateAuthority{
			ID: caid,
		},
		Template: &Template{
			TemplateType: TemplateTypeSSL,
			TemplateID:   templateID,
		},
	}
}
