package segwit

import (
	"encoding/base64"
	"encoding/binary"

	"github.com/cometbft/cometbft/crypto"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
)

var MagicBytes = []byte("Bitcoin Signed Message:\n")

func VarintBufNum(n uint64) []byte {
	var buf []byte
	if n < 253 {
		// buf = Buffer.alloc(1);
		// buf.writeUInt8(n, 0);
		buf = make([]byte, 1)
		buf[0] = byte(n)
	} else if n < 0x10000 {
		// buf = Buffer.alloc(1 + 2);
		// buf.writeUInt8(253, 0);
		// buf.writeUInt16LE(n, 1);
		buf = make([]byte, 1+2)
		buf[0] = 253
		binary.LittleEndian.PutUint16(buf[1:], uint16(n))
	} else if n < 0x100000000 {
		// buf = Buffer.alloc(1 + 4);
		// buf.writeUInt8(254, 0);
		// buf.writeUInt32LE(n, 1);
		buf = make([]byte, 1+4)
		buf[0] = 254
		binary.LittleEndian.PutUint32(buf[1:], uint32(n))
	} else {
		// buf = Buffer.alloc(1 + 8);
		// buf.writeUInt8(255, 0);
		// buf.writeInt32LE(n & -1, 1);
		// buf.writeUInt32LE(Math.floor(n / 0x100000000), 5);
		buf = make([]byte, 1+8)
		buf[0] = 255
		binary.LittleEndian.PutUint32(buf[1:], uint32(n&1))
		binary.LittleEndian.PutUint32(buf[5:], uint32(n/0x100000000))
	}
	return buf
}

func MagicHash(msg []byte) []byte {
	return magicHash(msg)
}
func magicHash(msg []byte) []byte {

	// const prefix1 = varintBufNum(MAGIC_BYTES.length);
	// const messageBuffer = Buffer.from(message);
	// const prefix2 = varintBufNum(messageBuffer.length);
	// const buf = Buffer.concat([prefix1, MAGIC_BYTES, prefix2, messageBuffer]);
	// return base.doubleSha256(buf);
	prefix1 := VarintBufNum(uint64(len(MagicBytes)))
	prefix2 := VarintBufNum(uint64(len(msg)))
	buf := append(prefix1, MagicBytes...)
	buf = append(buf, prefix2...)
	buf = append(buf, msg...)

	return crypto.Sha256(crypto.Sha256(buf))
}

// Sign creates an ECDSA signature on curve Secp256k1, using SHA256 on the msg.
func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	// derivedKey := secp256k1.PrivKey{
	// 	Key: privKey.Key,
	// }
	derivedKey, _ := btcec.PrivKeyFromBytes(privKey.Key)

	hash := MagicHash(msg)

	println("hash:", hash)

	sig, err := ecdsa.SignCompact(derivedKey, hash, true)
	println("inner sig:", base64.StdEncoding.EncodeToString(sig))
	return sig, err
	// signature := ecdsa.Sign(derivedKey, hash)
	// return signature.Serialize(), nil
	//return derivedKey.Sign(magicHash(msg))
}

// VerifySignature validates the signature.
// The msg will be hashed prior to signature verification.
func (pubKey *PubKey) VerifySignature(msg []byte, sigStr []byte) bool {
	pk, err := btcec.ParsePubKey(pubKey.Key)
	if err != nil {
		return false
	}
	println("gotSig:", base64.StdEncoding.EncodeToString(sigStr))
	// hash := magicHash(msg)
	// signature, err := ecdsa.ParseSignature(sigStr)
	// if err != nil {
	// 	return false
	// }
	// return signature.Verify(hash, pk)

	println("sigStr:", sigStr)
	hash := magicHash(msg)
	gotPubKey, gotCompressed, err := ecdsa.RecoverCompact(sigStr, hash)
	if err != nil {
		return false
	}
	if !gotCompressed {
		return false
	}
	return gotPubKey.IsEqual(pk)

}
