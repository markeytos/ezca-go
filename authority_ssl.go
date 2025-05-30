package ezca

import "github.com/google/uuid"

type SSLAuthority AuthorityTemplate

func NewSSLAuthority(caid, templateID uuid.UUID) *SSLAuthority {
	return &SSLAuthority{
		Authority: &Authority{
			ID: caid,
		},
		Template: &Template{
			TemplateType: TemplateTypeSSL,
			TemplateID:   templateID,
		},
	}
}
