package types_test

import (
	"github.com/cosmos/cosmos-sdk/types"
	sdk "github.com/cosmos/cosmos-sdk/types"
)

func (s *addressTestSuite) TestBitcoinAddressLength() {
	config := sdk.GetConfig()
	config.SetBech32PrefixForAccount("bc", sdk.Bech32PrefixAccPub)
	config.Seal()

	cosmos, err := types.AccAddressFromBech32("bc1s276jza93k0wfk04eevdyfdkztywvngt6w2n8u")
	s.Require().NoError(err)

	seg, err := types.AccAddressFromBech32("bc1qxy2kgdygjrsqtzq2n0yrf2493p83kkfjhx0wlh")
	s.Require().NoError(err)
	tap, err := types.AccAddressFromBech32("bc1pc8x2esk3pf0r99pd5qwv5javemjen987t67lc22rft88yhqmgjfsau2rzu")
	s.Require().NoError(err)

	s.T().Log("segwit address length", len(seg.Bytes()))
	s.T().Log("taproot address length", len(tap.Bytes()))
	s.T().Log("cosmos address length", len(cosmos.Bytes()))

}
