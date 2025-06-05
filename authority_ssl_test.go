package ezca

import (
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
)

func TestNewSSLAuthority(t *testing.T) {
	ssl := NewSSLAuthority(uuid.Nil, uuid.Nil)
	assert.Equal(t, ssl, &SSLAuthority{
		Authority: &Authority{
			ID: uuid.Nil,
		},
		Template: &Template{
			TemplateType: TemplateTypeSSL,
			TemplateID:   uuid.Nil,
		},
	})
}
