package envelope

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// RFC 3394 §4 test vectors. Each vector specifies a KEK, key data to wrap,
// and the expected wrapped output.

type wrapVector struct {
	name       string
	kekHex     string
	keyHex     string
	wrappedHex string
}

// RFC 3394 §4.1 — AES-128 wrapping a 128-bit key.
var rfcVector1 = wrapVector{
	name:       "TV1-AES128-wrap128",
	kekHex:     "000102030405060708090A0B0C0D0E0F",
	keyHex:     "00112233445566778899AABBCCDDEEFF",
	wrappedHex: "1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5",
}

// RFC 3394 §4.2 — AES-192 KEK wrapping a 128-bit key.
var rfcVector2 = wrapVector{
	name:       "TV2-AES192-wrap128",
	kekHex:     "000102030405060708090A0B0C0D0E0F1011121314151617",
	keyHex:     "00112233445566778899AABBCCDDEEFF",
	wrappedHex: "96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D",
}

// RFC 3394 §4.3 — AES-256 KEK wrapping a 128-bit key.
var rfcVector3 = wrapVector{
	name:       "TV3-AES256-wrap128",
	kekHex:     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
	keyHex:     "00112233445566778899AABBCCDDEEFF",
	wrappedHex: "64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7",
}

// RFC 3394 §4.4 — AES-192 KEK wrapping a 192-bit key.
var rfcVector4 = wrapVector{
	name:       "TV4-AES192-wrap192",
	kekHex:     "000102030405060708090A0B0C0D0E0F1011121314151617",
	keyHex:     "00112233445566778899AABBCCDDEEFF0001020304050607",
	wrappedHex: "031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2",
}

// RFC 3394 §4.5 — AES-256 KEK wrapping a 192-bit key.
var rfcVector5 = wrapVector{
	name:       "TV5-AES256-wrap192",
	kekHex:     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
	keyHex:     "00112233445566778899AABBCCDDEEFF0001020304050607",
	wrappedHex: "A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1",
}

// RFC 3394 §4.6 — AES-256 KEK wrapping a 256-bit key.
var rfcVector6 = wrapVector{
	name:       "TV6-AES256-wrap256",
	kekHex:     "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
	keyHex:     "00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
	wrappedHex: "28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21",
}

func mustDecodeHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic("mustDecodeHex: " + err.Error())
	}
	return b
}

func TestWrapUnwrap_RFC3394_Vectors(t *testing.T) {
	vectors := []wrapVector{rfcVector1, rfcVector2, rfcVector3, rfcVector4, rfcVector5, rfcVector6}

	for _, v := range vectors {
		t.Run(v.name, func(t *testing.T) {
			kek := mustDecodeHex(v.kekHex)
			key := mustDecodeHex(v.keyHex)
			expected := mustDecodeHex(v.wrappedHex)

			wrapped, err := Wrap(kek, key)
			require.NoError(t, err, "Wrap should not fail")
			assert.Equal(t, expected, wrapped, "Wrap output must match RFC 3394 test vector")

			unwrapped, err := Unwrap(kek, wrapped)
			require.NoError(t, err, "Unwrap should not fail")
			assert.Equal(t, key, unwrapped, "Unwrap should recover original key")
		})
	}
}

func TestUnwrap_WrongKEK_ReturnsErrUnwrapAuth(t *testing.T) {
	kek := mustDecodeHex(rfcVector6.kekHex)
	key := mustDecodeHex(rfcVector6.keyHex)

	wrapped, err := Wrap(kek, key)
	require.NoError(t, err)

	wrongKEK := make([]byte, len(kek))
	wrongKEK[0] ^= 0xFF

	_, err = Unwrap(wrongKEK, wrapped)
	assert.ErrorIs(t, err, ErrUnwrapAuth, "Unwrap with wrong KEK must return ErrUnwrapAuth")
}

func TestUnwrap_TamperedCiphertext_ReturnsErrUnwrapAuth(t *testing.T) {
	kek := mustDecodeHex(rfcVector6.kekHex)
	key := mustDecodeHex(rfcVector6.keyHex)

	wrapped, err := Wrap(kek, key)
	require.NoError(t, err)

	tampered := make([]byte, len(wrapped))
	copy(tampered, wrapped)
	tampered[len(tampered)-1] ^= 0x01

	_, err = Unwrap(kek, tampered)
	assert.ErrorIs(t, err, ErrUnwrapAuth)
}

func TestWrap_InvalidInputs(t *testing.T) {
	kek := make([]byte, 32)

	_, err := Wrap(kek, make([]byte, 17))
	assert.Error(t, err)

	_, err = Wrap(kek, make([]byte, 8))
	assert.Error(t, err)
}

func TestUnwrap_InvalidInputs(t *testing.T) {
	kek := make([]byte, 32)

	_, err := Unwrap(kek, make([]byte, 17))
	assert.Error(t, err)

	_, err = Unwrap(kek, make([]byte, 16))
	assert.Error(t, err)
}
