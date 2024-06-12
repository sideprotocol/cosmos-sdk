package types_test

import (
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/cosmos/cosmos-sdk/types"
)

func (s *addressTestSuite) TestBitcoinAddressLength() {
	config := types.GetConfig()
	config.SetBech32PrefixForAccount("cosmos", types.Bech32PrefixAccPub)
	config.SetBtcChainCfg(&chaincfg.MainNetParams)
	config.Seal()

	cosmos, err := types.AccAddressFromBech32("cosmos1jxv0u20scum4trha72c7ltfgfqef6nscj25050")
	s.Require().NoError(err)
	s.Require().Equal(20, len(cosmos.Bytes()))

	seg, err := types.AccAddressFromBech32("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
	s.Require().NoError(err)
	s.Require().Equal(33, len(seg.Bytes()))
	tap, err := types.AccAddressFromBech32("bc1pc8x2esk3pf0r99pd5qwv5javemjen987t67lc22rft88yhqmgjfsau2rzu")
	s.Require().NoError(err)
	s.Require().Equal(32, len(tap.Bytes()))

}
