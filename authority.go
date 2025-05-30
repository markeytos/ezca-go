package ezca

import (
	"github.com/google/uuid"
)

type Authority struct {
	ID           uuid.UUID `json:"CAID"` // Certificate Authority ID
	FriendlyName string    `json:"CAFriendlyName"`
}
