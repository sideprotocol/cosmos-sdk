package keyring

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cosmos/cosmos-sdk/crypto/hd"
	"github.com/cosmos/cosmos-sdk/crypto/keys/segwit"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/stretchr/testify/require"
)

func TestKeyManagementKeyRingForSegWit(t *testing.T) {
	cdc := getCodec()
	tempDir := t.TempDir()
	kb, err := New("keybasename", "test", tempDir, nil, cdc)
	require.NoError(t, err)
	require.NotNil(t, cdc)

	hdPath := "m/84'/0'/0'/0/0"

	algo := hd.SegWit
	n1, n2, n3 := "personal", "business", "other"

	// Check empty state
	records, err := kb.List()
	require.NoError(t, err)
	require.Empty(t, records)

	_, _, err = kb.NewMnemonic(n1, English, hdPath, DefaultBIP39Passphrase, notSupportedAlgo{})
	require.Error(t, err, "ed25519 keys are currently not supported by keybase")

	// create some keys
	_, err = kb.Key(n1)
	require.Error(t, err)
	// save localKey with "n1`"
	k, _, err := kb.NewMnemonic(n1, English, hdPath, DefaultBIP39Passphrase, algo)
	require.NoError(t, err)
	require.Equal(t, n1, k.Name)

	// save localKey with "n2"
	k1, _, err := kb.NewMnemonic(n2, English, hdPath, DefaultBIP39Passphrase, algo)
	require.NoError(t, err)
	require.Equal(t, n2, k1.Name)

	k2, err := kb.Key(n2)
	require.NoError(t, err)
	_, err = kb.Key(n3)
	require.NotNil(t, err)
	addr, err := k2.GetAddress()
	require.NoError(t, err)
	_, err = kb.KeyByAddress(addr)
	require.NoError(t, err)
	addr, err = sdk.AccAddressFromBech32("cosmos1yq8lgssgxlx9smjhes6ryjasmqmd3ts2559g0t")
	require.NoError(t, err)
	_, err = kb.KeyByAddress(addr)
	require.Error(t, err)

	// list shows them in order
	keyS, err := kb.List()
	require.NoError(t, err)
	require.Equal(t, 2, len(keyS))
	// note these are in alphabetical order
	require.Equal(t, n2, keyS[0].Name)
	require.Equal(t, n1, keyS[1].Name)

	key1, err := k2.GetPubKey()
	require.NoError(t, err)
	require.NotNil(t, key1)
	key2, err := keyS[0].GetPubKey()
	require.NoError(t, err)
	require.NotNil(t, key2)
	require.Equal(t, key1, key2)

	// deleting a key removes it
	err = kb.Delete("bad name")
	require.NotNil(t, err)
	err = kb.Delete(n1)
	require.NoError(t, err)
	keyS, err = kb.List()
	require.NoError(t, err)
	require.Equal(t, 1, len(keyS))
	_, err = kb.Key(n1)
	require.Error(t, err)

	// create an offline key
	o1 := "offline"
	priv1 := segwit.GenPrivKey()
	pub1 := priv1.PubKey()
	k3, err := kb.SaveOfflineKey(o1, pub1)
	require.Nil(t, err)

	key1, err = k3.GetPubKey()
	require.NoError(t, err)
	require.NotNil(t, key1)
	require.Equal(t, pub1, key1)

	require.Equal(t, o1, k3.Name)
	keyS, err = kb.List()
	require.NoError(t, err)
	require.Equal(t, 2, len(keyS))

	// delete the offline key
	err = kb.Delete(o1)
	require.NoError(t, err)
	keyS, err = kb.List()
	require.NoError(t, err)
	require.Equal(t, 1, len(keyS))

	// create some random directory inside the keyring directory to check migrate ignores
	// all files other than *.info
	newPath := filepath.Join(tempDir, "random")
	require.NoError(t, os.Mkdir(newPath, 0o755))
	items, err := os.ReadDir(tempDir)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(items), 2)
	_, err = kb.List()
	require.NoError(t, err)

	// addr cache gets nuked - and test skip flag
	require.NoError(t, kb.Delete(n2))
}
