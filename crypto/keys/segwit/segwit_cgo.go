package segwit

import (
	"crypto"
	"encoding/binary"

	"github.com/cosmos/cosmos-sdk/crypto/keys/secp256k1"
)

var MagicBytes = []byte("Bitcoin Signed Message:\n")

func varintBufNum(n uint64) []byte {
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

func magicHash(msg []byte) []byte {

	// const prefix1 = varintBufNum(MAGIC_BYTES.length);
	// const messageBuffer = Buffer.from(message);
	// const prefix2 = varintBufNum(messageBuffer.length);
	// const buf = Buffer.concat([prefix1, MAGIC_BYTES, prefix2, messageBuffer]);
	// return base.doubleSha256(buf);
	prefix1 := varintBufNum(uint64(len(MagicBytes)))
	prefix2 := varintBufNum(uint64(len(msg)))
	buf := append(prefix1, MagicBytes...)
	buf = append(buf, prefix2...)
	buf = append(buf, msg...)

	return crypto.SHA256.New().Sum(buf)
}

// Sign creates an ECDSA signature on curve Secp256k1, using SHA256 on the msg.
func (privKey *PrivKey) Sign(msg []byte) ([]byte, error) {
	derivedKey := secp256k1.PrivKey{
		Key: privKey.Key,
	}
	return derivedKey.Sign(magicHash(msg))
}

// VerifySignature validates the signature.
// The msg will be hashed prior to signature verification.
func (pubKey *PubKey) VerifySignature(msg []byte, sigStr []byte) bool {
	derivedPubKey := secp256k1.PubKey{
		Key: pubKey.Key,
	}
	hash := magicHash(msg)
	if derivedPubKey.VerifySignature(hash, sigStr) {
		return true
	}

	return derivedPubKey.VerifySignature(crypto.SHA256.New().Sum(hash), sigStr)
}
