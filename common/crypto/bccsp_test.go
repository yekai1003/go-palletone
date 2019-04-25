package crypto

import (
	"github.com/palletone/go-palletone/bccsp"
	"github.com/palletone/go-palletone/bccsp/factory"
	"github.com/stretchr/testify/assert"

	//"os"
	"fmt"
	"os"
	"testing"

	"github.com/palletone/go-palletone/common/log"
)

func TestEcdsaP256(t *testing.T) {
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

	privKey, err := csp.KeyGen(&bccsp.ECDSAP256KeyGenOpts{Password: []byte("1")})
	assert.Nil(t, err)

	privKeyB, err := privKey.Bytes()
	assert.Nil(t, err)
	t.Logf("Private Key:%x,SKI:%x", privKeyB, privKey.SKI())

	getPrivKey, err := csp.GetKey(privKey.SKI(), &bccsp.ECDSAGetKeyOpts{Password: []byte("1")})
	assert.Equal(t, privKey, getPrivKey)

	pubKey, _ := privKey.PublicKey()
	pubKeyB, _ := pubKey.Bytes()
	t.Logf("PubKey:%x,len:%d, SKI:%X", pubKeyB, len(pubKeyB), pubKey.SKI())
	signature, err := csp.Sign(privKey, hash1, nil)
	t.Logf("Signature:%x", signature)
	valid, err := csp.Verify(pubKey, signature, hash1, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	t.Log(valid)
	priKey2, err := csp.KeyImport(privKeyB, &bccsp.ECDSAPrivateKeyImportOpts{Format: bccsp.ECDSAPrivateKeyFormat_DER, Password: []byte("2")})
	assert.Nil(t, err)
	privKey2B, _ := priKey2.Bytes()
	assert.Equal(t, privKeyB, privKey2B)
	pubKey2, err := csp.KeyImport(pubKeyB, &bccsp.ECDSAPKIXPublicKeyImportOpts{Temporary: true})
	assert.Nil(t, err)
	t.Log(pubKey2)
	key3, err := csp.GetKey(pubKey.SKI(), &bccsp.ECDSAGetKeyOpts{Password: []byte("3")})
	assert.NotNil(t, err)
	assert.Nil(t, key3)
	//t.Logf("PrivKey:%#v", key3)
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
	assert.Nil(t, err)
	privKeyB, err := privKey.Bytes()
	assert.NotNil(t, err)
	t.Logf("Private Key:%x,SKI:%x", privKeyB, privKey.SKI())
	getPrivKey, err := csp.GetKey(privKey.SKI(), &bccsp.ECDSAGetKeyOpts{Password: []byte("1")})
	assert.Nil(t,err)
	assert.Equal(t, privKey, getPrivKey)

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
	pubkey2, err := csp.KeyImport(pubKeyB, &bccsp.GMSM2PublicKeyImportOpts{})
	assert.Nil(t, err)
	pubkey2B, _ := pubkey2.Bytes()
	assert.Equal(t, pubKeyB, pubkey2B)
}

func TestS256(t *testing.T) {
	f := &factory.SWFactory{}
	var pwd []byte=[]byte("1")
	opts := &factory.FactoryOpts{
		SwOpts: &factory.SwOpts{
			SecLevel:     256,
			HashFamily:   "SHA3",
			FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: os.TempDir()},
		},
	}
	hash1 := []byte("Devin")
	csp, err := f.Get(opts)
	assert.NoError(t, err)
	assert.NotNil(t, csp)
	t.Log("Try to generate new key")
	privKey, err := csp.KeyGen(&bccsp.ECDSAS256KeyGenOpts{Password: pwd})
	assert.Nil(t, err)
	getPrivKey, err := csp.GetKey(privKey.SKI(), &bccsp.ECDSAGetKeyOpts{Password: pwd})
	assert.Nil(t,err)
	assert.Equal(t, privKey, getPrivKey)

	privKeyB, err := privKey.Bytes()

	assert.Nil(t, err)
	t.Logf("Private Key:%x,SKI:%x", privKeyB, privKey.SKI())
	pubKey, _ := privKey.PublicKey()
	pubKeyB, _ := pubKey.Bytes()
	t.Logf("PubKey:%x,len:%d,SKI:%x", pubKeyB, len(pubKeyB), pubKey.SKI())
	signature, err := csp.Sign(privKey, hash1, nil)
	t.Logf("Signature:%x,len:%d", signature, len(signature))
	valid, err := csp.Verify(pubKey, signature, hash1, nil)
	if err != nil {
		t.Fatalf("Failed verifying ECDSA signature [%s]", err)
	}
	t.Log(valid)
	priKey2, err := csp.KeyImport(privKeyB, &bccsp.ECDSAPrivateKeyImportOpts{Format: bccsp.ECDSAPrivateKeyFormat_Hex})
	assert.Nil(t, err)
	privKey2B, _ := priKey2.Bytes()
	assert.Equal(t, privKeyB, privKey2B)
	pubKey2, err := csp.KeyImport(pubKeyB, &bccsp.ECDSAS256PublicKeyImportOpts{})
	assert.Nil(t, err)
	t.Log(pubKey2.Bytes())
	key3, err := csp.GetKey(pubKey.SKI(), &bccsp.ECDSAGetKeyOpts{Password: pwd})
	assert.Nil(t, err)
	t.Log(key3.Bytes())
}

func TestMain(m *testing.M) {
	_, err := Init(HashType_SHA3_256, CryptoType_ECDSA_S256, os.TempDir())
	if err != nil {
		log.Error(err.Error())
	}
	os.Exit(m.Run())
}
func TestHash(t *testing.T) {
	str := "Devin"
	hash := HashResult([]byte(str))
	t.Log(hash.String())
}
func BenchmarkHash(b *testing.B) {
	for i := 0; i < b.N; i++ {
		str := fmt.Sprintf("Devin%d", i)
		hash := HashResult([]byte(str))
		b.Log(str, hash.String())
	}
}
func TestSignByAddress(t *testing.T) {
	pwd:=[]byte("1")
	hash := []byte("Devin")
	addr, err := GenerateNewAddress(pwd)
	assert.Nil(t, err)
	t.Logf("New Address:%s", addr.String())
	signature, err := SignByAddress(hash, addr,pwd)
	assert.Nil(t, err)
	t.Logf("Signature:%x", signature)

	pubKey, err := GetPubKeyByAddress(addr,pwd)
	assert.Nil(t, err)
	t.Logf("Public key:%x", pubKey)
	pass := VerifySign(pubKey, hash, signature)
	assert.True(t, pass)
}
func BenchmarkSignByAddress(b *testing.B) {
	addr, err := GenerateNewAddress(nil)
	assert.Nil(b, err)
	b.Logf("New Address:%s", addr.String())
	for i := 0; i < b.N; i++ {
		hash := []byte(fmt.Sprintf("Devin%d", i))
		signature, err := SignByAddress(hash, addr,nil)
		assert.Nil(b, err)
		b.Log("Signature", signature)
	}
}
