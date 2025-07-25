package ezca

import (
	"errors"

	"github.com/google/uuid"
	"github.com/markeytos/ezca-go/internal/api"
)

type Authority struct {
	ID            uuid.UUID     `json:"id"`
	FriendlyName  string        `json:"friendly_name"`
	KeyType       KeyType       `json:"key_type"`
	HashAlgorithm HashAlgorithm `json:"hash_algorithm"`
	IsPublic      bool          `json:"is_public"`
	IsRoot        bool          `json:"is_root"`
}

func (a *Authority) populateWithInternalAuthority(s *api.Authority) error {
	if a == nil || s == nil {
		return errors.New("cannot populate authority due to nil inputs")
	}

	a.ID = s.ID
	a.FriendlyName = s.FriendlyName
	a.KeyType = KeyType(s.KeyType)
	a.HashAlgorithm = HashAlgorithm(s.HashAlgorithm)

	switch s.Type {
	case api.CATypePublic:
		a.IsPublic = true
	case api.CATypePrivate:
		a.IsPublic = false
	default:
		return errors.ErrUnsupported
	}

	switch s.Tier {
	case api.CATierRoot:
		a.IsRoot = true
	case api.CATierSubordinate:
		a.IsRoot = false
	default:
		return errors.ErrUnsupported
	}

	return nil
}

type KeyType string

const (
	KeyTypeRSA2048 KeyType = "RSA 2048"
)

type HashAlgorithm string

const (
	HashAlgorithmSHA256 HashAlgorithm = "SHA256"
)

func newFromInternalAuthority(ia *api.Authority) (*Authority, error) {
	a := &Authority{}
	err := a.populateWithInternalAuthority(ia)
	return a, err
}
