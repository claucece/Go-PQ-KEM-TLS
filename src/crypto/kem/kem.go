package kem

import (
	"circl/dh/sidh"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/curve25519"
)

// ID identifies each flavor of KEM.
type ID uint16

const (
	// KEM25519 is X25519 as a KEM. Not quantum-safe.
	KEM25519 ID = 0x01fb
	// CSIDH is a post-quantum NIKE
	CSIDH ID = 0x01fc
	// Kyber512 is a post-quantum KEM based on MLWE
	Kyber512 ID = 0x01fd
	// SIKEp434 is a post-quantum KEM
	SIKEp434 ID = 0x01fe

	// minimum
	minKEM = KEM25519
	// maximum
	maxKEM = SIKEp434
)

// PrivateKey is a private key.
type PrivateKey struct {
	KEMId      ID
	PrivateKey []byte
}

// PublicKey is a public key.
type PublicKey struct {
	KEMId     ID
	PublicKey []byte
}

// MarshalPublicKey returns the byte representation of a public key.
func MarshalPublicKey(pubKey PublicKey) []byte {
	buf := make([]byte, 4+len(pubKey.PublicKey))
	binary.LittleEndian.PutUint16(buf, uint16(pubKey.KEMId))
	copy(buf[4:], pubKey.PublicKey)
	return buf
}

// UnmarshalPublicKey produces a PublicKey from a byte array.
func UnmarshalPublicKey(input []byte) (PublicKey, error) {
	id := ID(binary.LittleEndian.Uint16(input[:4]))
	if id < minKEM || id > maxKEM {
		return PublicKey{}, errors.New("Invalid KEM type")
	}

	return PublicKey{
		KEMId:     id,
		PublicKey: input,
	}, nil
}

// GenerateKey generates a keypair for a given KEM.
// It returns a public and private key.
func GenerateKey(rand io.Reader, kemID ID) (PublicKey, PrivateKey, error) {
	switch kemID {
	case KEM25519:
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return PublicKey{}, PrivateKey{}, err
		}
		publicKey, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return PublicKey{}, PrivateKey{}, err
		}
		return PublicKey{KEMId: kemID, PublicKey: publicKey}, PrivateKey{KEMId: kemID, PrivateKey: privateKey}, nil
	case SIKEp434:
		privateKey := sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
		publicKey := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		if err := privateKey.Generate(rand); err != nil {
			return PublicKey{}, PrivateKey{}, err
		}
		privateKey.GeneratePublicKey(publicKey)

		pubBytes := make([]byte, publicKey.Size())
		privBytes := make([]byte, privateKey.Size())
		publicKey.Export(pubBytes)
		privateKey.Export(privBytes)
		return PublicKey{KEMId: kemID, PublicKey: pubBytes}, PrivateKey{KEMId: kemID, PrivateKey: privBytes}, nil
	default:
		return PublicKey{}, PrivateKey{}, fmt.Errorf("crypto/kem: internal error: unsupported KEM %d", kemID)
	}

}

// Encapsulate returns a shared secret and a ciphertext.
func Encapsulate(rand io.Reader, pk *PublicKey) ([]byte, []byte, error) {
	switch pk.KEMId {
	case KEM25519:
		privateKey := make([]byte, curve25519.ScalarSize)
		if _, err := io.ReadFull(rand, privateKey); err != nil {
			return nil, nil, err
		}
		ciphertext, err := curve25519.X25519(privateKey, curve25519.Basepoint)
		if err != nil {
			return nil, nil, err
		}
		sharedSecret, err := curve25519.X25519(privateKey, pk.PublicKey)
		if err != nil {
			return nil, nil, err
		}
		return sharedSecret, ciphertext, nil
	case SIKEp434:
		kem := sidh.NewSike434(rand)
		sikepk := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		sikepk.Import(pk.PublicKey)
		ct := make([]byte, kem.CiphertextSize())
		ss := make([]byte, kem.SharedSecretSize())
		kem.Encapsulate(ct, ss, sikepk)
		return ss, ct, nil
	default:
		return nil, nil, errors.New("crypto/kem: internal error: unsupported KEM in Encapsulate")
	}
}

// Decapsulate generates the shared secret.
func Decapsulate(privateKey *PrivateKey, ciphertext []byte) ([]byte, error) {
	switch privateKey.KEMId {
	case KEM25519:
		sharedSecret, err := curve25519.X25519(privateKey.PrivateKey, ciphertext)
		if err != nil {
			return nil, err
		}
		return sharedSecret, nil
	case SIKEp434:
		kem := sidh.NewSike434(nil)
		sikesk := sidh.NewPrivateKey(sidh.Fp434, sidh.KeyVariantSike)
		sikesk.Import(privateKey.PrivateKey)
		sikepk := sidh.NewPublicKey(sidh.Fp434, sidh.KeyVariantSike)
		sikesk.GeneratePublicKey(sikepk)
		ss := make([]byte, kem.SharedSecretSize())
		kem.Decapsulate(ss, sikesk, sikepk, ciphertext)
		return ss, nil
	default:
		return nil, errors.New("crypto/kem: internal error: unsupported KEM in Decapsulate")
	}
}
