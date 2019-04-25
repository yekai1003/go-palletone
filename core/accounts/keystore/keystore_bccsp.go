package keystore

import (
	"path/filepath"

	"github.com/palletone/go-palletone/common"
	"github.com/palletone/go-palletone/common/crypto"
	"github.com/pborman/uuid"
)

type keyStoreBccsp struct {
	cl          *crypto.CryptoLib
	keysDirPath string
}

func (ks *keyStoreBccsp) GetKey(addr common.Address, filename string, auth string) (*Key, error) {
	key, err := ks.cl.GetKey(addr, []byte(auth))
	if err != nil {
		return nil, err
	}
	id := uuid.NewRandom()
	prvKeyB, _ := key.Bytes()
	pubKey,_:=key.PublicKey()
	pubKeyB,_:=pubKey.Bytes()
	thekey := &Key{
		Id:          id,
		Address:     common.NewAddress(key.SKI(), common.PublicKeyHash),
		PrivateKeyB: prvKeyB,
		PublicKeyB:pubKeyB,

	}
	return thekey, nil
}

// Writes and encrypts the key.
func (ks *keyStoreBccsp) StoreKey(filename string, k *Key, auth string) error {
	err := ks.cl.StoreKey(k.PrivateKeyB, []byte(auth))
	return err
}

// Joins filename with the key directory unless it is already absolute.
func (ks *keyStoreBccsp) JoinPath(filename string) string {
	if filepath.IsAbs(filename) {
		return filename
	} else {
		return filepath.Join(ks.keysDirPath, filename)
	}
}
