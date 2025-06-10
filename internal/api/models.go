package api

import "github.com/google/uuid"

type Authority struct {
	ID            uuid.UUID `json:"CAID"` // Certificate Authority ID
	FriendlyName  string    `json:"CAFriendlyName"`
	KeyType       string    `json:"CAKeyType"`
	HashAlgorithm string    `json:"CAHashing"`
	Type          CAType    `json:"CAType"`
	Tier          CATier    `json:"CATier"`
}

type AuthorityTemplate struct {
	*Authority
	TemplateID   uuid.UUID    `json:"TemplateID"`     // Template ID
	TemplateType TemplateType `json:"CATemplateType"` // Template Type
}

type CAType string

const (
	CATypePublic  CAType = "PublicCA"
	CATypePrivate CAType = "PrivateCA"
)

type CATier string

const (
	CATierSubordinate CATier = "SubordinateCA"
	CATierRoot        CATier = "RootCA"
)

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
