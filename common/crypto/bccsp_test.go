package crypto

import (
	"github.com/palletone/go-palletone/bccsp"
	"github.com/palletone/go-palletone/bccsp/factory"
	"github.com/stretchr/testify/assert"
	"os"
	"testing"
)

func TestSWFactoryGet(t *testing.T) {
	f := &factory.SWFactory{}

	opts := &factory.FactoryOpts{
		SwOpts: &factory.SwOpts{
			SecLevel:     256,
			HashFamily:   "SHA3",
			FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: os.TempDir()},
		},
	}

	csp, err := f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)
	hashOpt, err := bccsp.GetHashOpt("SHA3_256")
	hf, err := csp.GetHash(hashOpt)
	hf.Write([]byte("Devin"))
	hash1 := hf.Sum(nil)
	hash2, err := csp.Hash([]byte("Devin"), hashOpt)
	assert.Nil(t, err)
	assert.Equal(t, hash1, hash2)
	t.Logf("Hash Devin result:%x", hash1)

	privKey, err := csp.KeyGen(&bccsp.ECDSAP256KeyGenOpts{})
	privKeyB, _ := privKey.Bytes()
	assert.Nil(t, err)
	t.Logf("Private Key:%x,SKI:%x", privKeyB, privKey.SKI())
	pubKey, _ := privKey.PublicKey()
	pubKeyB, _ := pubKey.Bytes()
	t.Logf("PubKey:%x,SKI:%X", pubKeyB, pubKey.SKI())
	signature, err := csp.Sign(privKey, hash1, nil)
	t.Logf("Signature:%x", signature)
	valid, err := csp.Verify(pubKey, signature, hash1, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	t.Log(valid)
}
func TestGmFactoryGet(t *testing.T) {
	f := &factory.GMFactory{}

	opts := &factory.FactoryOpts{
		SwOpts: &factory.SwOpts{
			SecLevel:     256,
			HashFamily:   "GMSM3",
			FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: os.TempDir()},
		},
	}

	csp, err := f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)
	hashOpt, err := bccsp.GetHashOpt("GMSM3")
	hf, err := csp.GetHash(hashOpt)
	hf.Write([]byte("Devin"))
	hash1 := hf.Sum(nil)
	hash2, err := csp.Hash([]byte("Devin"), hashOpt)
	assert.Nil(t, err)
	assert.Equal(t, hash1, hash2)
	t.Logf("Hash Devin result:%x", hash1)

	privKey, err := csp.KeyGen(&bccsp.GMSM2KeyGenOpts{})
	privKeyB, _ := privKey.Bytes()
	assert.Nil(t, err)
	t.Logf("Private Key:%x,SKI:%x", privKeyB, privKey.SKI())
	pubKey, _ := privKey.PublicKey()
	pubKeyB, _ := pubKey.Bytes()
	t.Logf("PubKey:%x,SKI:%X", pubKeyB, pubKey.SKI())
	signature, err := csp.Sign(privKey, hash1, nil)
	t.Logf("Signature:%x", signature)
	valid, err := csp.Verify(pubKey, signature, hash1, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	t.Log(valid)
}
