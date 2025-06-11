package ezca

import "github.com/google/uuid"

type SSLAuthority struct {
	*Authority
	TemplateID uuid.UUID `json:"template_id"`
}
