package keystore

import (
	"github.com/palletone/go-palletone/common"
	"github.com/pborman/uuid"
	"path/filepath"
	"github.com/palletone/go-palletone/common/crypto"
)

type keyStoreBccsp struct {
	cl *crypto.CryptoLib
	keysDirPath string
}
func (ks *keyStoreBccsp)GetKey(addr common.Address, filename string, auth string) (*Key, error){
	key,err:=ks.cl.GetKey(addr,auth)
	if err!=nil{
		return nil,err
	}
	id := uuid.NewRandom()
	prvKeyB,_:=key.Bytes()
	thekey := &Key{
		Id:         id,
		Address:    common.NewAddress(key.SKI(),common.PublicKeyHash),
		PrivateKeyB: prvKeyB,
	}
	return thekey,nil
}
// Writes and encrypts the key.
func (ks *keyStoreBccsp)StoreKey(filename string, k *Key, auth string) error {
	err := ks.cl.StoreKey(k.PrivateKeyB, auth)
	return err
}
// Joins filename with the key directory unless it is already absolute.
func (ks *keyStoreBccsp)JoinPath(filename string) string{
	if filepath.IsAbs(filename) {
		return filename
	} else {
		return filepath.Join(ks.keysDirPath, filename)
	}
}
