package bech32

import (
	"fmt"
	"strings"

	"github.com/cosmos/btcutil/bech32"
)

// ConvertAndEncode converts from a base256 encoded byte string to base32 encoded byte string and then to bech32.
func ConvertAndEncode(hrp string, data []byte) (string, error) {
	bitcoinBech32, err := bech32.Encode(hrp, data)
	if IsBitCoinAddr(bitcoinBech32) && err == nil {
		return bitcoinBech32, err
	}
	converted, err := bech32.ConvertBits(data, 8, 5, true)
	if err != nil {
		return "", fmt.Errorf("encoding bech32 failed: %w", err)
	}
	return bech32.Encode(hrp, converted)
}

// DecodeAndConvert decodes a bech32 encoded string and converts to base256 encoded bytes.
func DecodeAndConvert(bech string) (string, []byte, error) {
	// println("bech32.Decode(bech, 1000)", bech)
	isBitcoin := IsBitCoinAddr(bech)
	var hrp string
	var data []byte
	var err error
	if isBitcoin {
		hrp, data, err = bech32.Decode(bech, 1000)
	} else {
		hrp, data, err = bech32.Decode(bech, 1023)
	}

	if err != nil {
		if err != nil {
			return "", nil, fmt.Errorf("decoding bech32 failed: %w", err)
		}
	}

	if isBitcoin {
		return hrp, data, nil
	}

	converted, err := bech32.ConvertBits(data, 5, 8, false)
	if err != nil {
		return "", nil, fmt.Errorf("decoding bech32 failed: %w", err)
	}
	return hrp, converted, nil
}

func IsBitCoinAddr(bech string) bool {
	return strings.Contains(bech, "bc1q") && len(bech) == 42
}
