package ezca

import "github.com/google/uuid"

type Template struct {
	TemplateID   uuid.UUID    `json:"TemplateID"`     // Template ID
	TemplateType TemplateType `json:"CATemplateType"` // Template Type
}

type TemplateType string

const (
	TemplateTypePublicCA      TemplateType = "Public CA Template"
	TemplateTypeSSL           TemplateType = "SSL Template"
	TemplateTypeSCEP          TemplateType = "SCEP Template"
	TemplateTypeWorkstation   TemplateType = "Workstation Template"
	TemplateTypeSmartCard     TemplateType = "Smart Card Template"
	TemplateTypeCodeSigning   TemplateType = "CodeSigning Template"
	TemplateTypeSubordinateCA TemplateType = "Subordinate CA Template"
	TemplateTypeIoTEdgeCA     TemplateType = "IoT Edge CA Template"
)
