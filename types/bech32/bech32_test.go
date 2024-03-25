package bech32_test

import (
	"bytes"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/cosmos/cosmos-sdk/types/bech32"
)

func TestEncodeAndDecode(t *testing.T) {
	sum := sha256.Sum256([]byte("hello world\n"))
	ss := "shasum"

	bech, err := bech32.ConvertAndEncode(ss, sum[:])
	require.NoError(t, err)

	hrp, data, err := bech32.DecodeAndConvert(bech)
	require.NoError(t, err)

	require.Equal(t, hrp, ss, "Invalid hrp")
	require.True(t, bytes.Equal(data, sum[:]), "Invalid decode")
}

func FuzzDecodeAndConvert(f *testing.F) {
	if testing.Short() {
		f.Skip()
	}

	f.Add("shasum149yfqne0parehrupja55kvqcfvxja5wpe54pas8mshffngvj53rs93fk75")
	f.Add("bech321er8m900ayvv9rg5r6ush4nzvqhj4p9tqnxqkxaaxrs4ueuvhurcs4x3j4j")
	f.Add("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")

	f.Fuzz(func(t *testing.T, str string) {
		_, _, _ = bech32.DecodeAndConvert(str)
	})
}

func TestDecodeString(t *testing.T) {
	hrp, _, err := bech32.DecodeAndConvert("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq")
	require.NoError(t, err)
	require.Equal(t, "bc", hrp)
	hrp, _, err = bech32.DecodeAndConvert("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr")
	require.NoError(t, err)
	require.Equal(t, "bc", hrp)

}
