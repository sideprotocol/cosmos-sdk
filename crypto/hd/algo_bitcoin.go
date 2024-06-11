package hd

import (
	"strings"

	"github.com/cosmos/go-bip39"

	"github.com/cosmos/cosmos-sdk/crypto/keys/segwit"
	"github.com/cosmos/cosmos-sdk/crypto/keys/taproot"
	"github.com/cosmos/cosmos-sdk/crypto/types"
)

const (
	SegWitType  = PubKeyType("segwit")
	TaprootType = PubKeyType("taproot")
)

var (
	SegWit  = segWigAlgo{}
	Taproot = taprootAlgo{}
)

type segWigAlgo struct{}

func (s segWigAlgo) Name() PubKeyType {
	return SegWitType
}

// Derive derives and returns the secp256k1 private key for the given seed and HD path.
func (s segWigAlgo) Derive() DeriveFn {
	return func(mnemonic string, bip39Passphrase, hdPath string) ([]byte, error) {
		if !strings.HasPrefix(hdPath, "m/84'") {
			panic("Invalid HD path for SegWit")
		}
		seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if err != nil {
			return nil, err
		}

		masterPriv, ch := ComputeMastersFromSeed(seed)
		if len(hdPath) == 0 {
			return masterPriv[:], nil
		}
		derivedKey, err := DerivePrivateKeyForPath(masterPriv, ch, hdPath)

		return derivedKey, err
	}
}

// Generate generates a secp256k1 private key from the given bytes.
func (s segWigAlgo) Generate() GenerateFn {
	return func(bz []byte) types.PrivKey {
		bzArr := make([]byte, segwit.PrivKeySize)
		copy(bzArr, bz)

		return &segwit.PrivKey{Key: bzArr}
	}
}

type taprootAlgo struct{}

func (s taprootAlgo) Name() PubKeyType {
	return TaprootType
}

// Derive derives and returns the secp256k1 private key for the given seed and HD path.
func (s taprootAlgo) Derive() DeriveFn {
	return func(mnemonic string, bip39Passphrase, hdPath string) ([]byte, error) {
		if !strings.HasPrefix(hdPath, "m/86'") {
			panic("Invalid HD path for Taproot")
		}
		seed, err := bip39.NewSeedWithErrorChecking(mnemonic, bip39Passphrase)
		if err != nil {
			return nil, err
		}

		masterPriv, ch := ComputeMastersFromSeed(seed)
		if len(hdPath) == 0 {
			return masterPriv[:], nil
		}
		derivedKey, err := DerivePrivateKeyForPath(masterPriv, ch, hdPath)

		return derivedKey, err
	}
}

// Generate generates a secp256k1 private key from the given bytes.
func (s taprootAlgo) Generate() GenerateFn {
	return func(bz []byte) types.PrivKey {
		bzArr := make([]byte, taproot.PrivKeySize)
		copy(bzArr, bz)

		return &taproot.PrivKey{Key: bzArr}
	}
}

// NewFundraiserParams creates a BIP parameter object from the params:
// m / purpose / coinType' / account' / 0 / address_index
// The fixed parameters (purpose', coin_type', and change) are determined by what was used in the fundraiser.
func NewFundraiserParamsWithPurpose(purpose, account, coinType, addressIdx uint32) *BIP44Params {
	return NewParams(purpose, coinType, account, false, addressIdx)
}

func CreateHDPathWithPurpose(purpose, coinType, account, index uint32) *BIP44Params {
	return NewFundraiserParamsWithPurpose(purpose, account, coinType, index)
}
