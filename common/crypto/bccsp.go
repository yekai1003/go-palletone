/*
 *
 *    This file is part of go-palletone.
 *    go-palletone is free software: you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License as published by
 *    the Free Software Foundation, either version 3 of the License, or
 *    (at your option) any later version.
 *    go-palletone is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *    You should have received a copy of the GNU General Public License
 *    along with go-palletone.  If not, see <http://www.gnu.org/licenses/>.
 * /
 *
 *  * @author PalletOne core developer <dev@pallet.one>
 *  * @date 2018-2019
 *
 */

package crypto

import (
	"github.com/palletone/go-palletone/bccsp"
	"github.com/palletone/go-palletone/bccsp/factory"
	"github.com/palletone/go-palletone/common"

	"hash"
	"os"
	"path/filepath"

	"github.com/palletone/go-palletone/common/log"
)

type HashType byte

const (
	HashType_SHA3_256 HashType = 0
	HashType_GM3      HashType = 1
)

type CryptoType byte

const (
	CryptoType_ECDSA_S256 CryptoType = 0
	CryptoType_GM2_256    CryptoType = 1
	CryptoType_ECDSA_P256 CryptoType = 2
)

type CryptoLib struct {
	csp                 bccsp.BCCSP
	hashOpt             bccsp.HashOpts
	keyImportOpt        bccsp.KeyImportOpts
	tempPubkeyImportOpt bccsp.KeyImportOpts
	keyGenOpt           bccsp.KeyGenOpts
	tempkeyGenOpt       bccsp.KeyGenOpts
	cacheAddrPriKey     map[common.Address]bccsp.Key
	cacheAddrPubKey     map[common.Address]bccsp.Key
}

var myCryptoLib *CryptoLib

func InitCryptoLib(hashType string, cryptoType string, keystorePath string) (*CryptoLib, error) {
	hashTp := HashType_SHA3_256
	if hashType == "GM3" {
		hashTp = HashType_GM3
	}
	cryptoTp := CryptoType_ECDSA_S256
	if cryptoType == "GM2_256" {
		cryptoTp = CryptoType_GM2_256
	} else if cryptoType == "ECDSA_P256" {
		cryptoTp = CryptoType_ECDSA_P256
	}
	return Init(hashTp, cryptoTp, keystorePath)
}
func InitDefaultCryptoLib() (*CryptoLib, error) {
	dir, _ := os.Getwd()
	return Init(HashType_SHA3_256, CryptoType_ECDSA_S256, filepath.Join(dir, "palletone", "keystore"))
}
func Init(hashType HashType, cryptoType CryptoType, keystorePath string) (*CryptoLib, error) {
	log.Debug("Try to initial bccsp instance.")
	cryptoLib := &CryptoLib{}
	cryptoLib.cacheAddrPriKey = make(map[common.Address]bccsp.Key)
	cryptoLib.cacheAddrPubKey = make(map[common.Address]bccsp.Key)
	f := &factory.SWFactory{}
	opts := &factory.FactoryOpts{
		SwOpts: &factory.SwOpts{
			SecLevel:     256,
			HashFamily:   "SHA3",
			FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: keystorePath},
		},
	}
	var err error
	cryptoLib.hashOpt, err = bccsp.GetHashOpt("SHA3_256")
	if err != nil {
		return nil, err
	}
	if hashType == HashType_GM3 {
		opts = &factory.FactoryOpts{
			SwOpts: &factory.SwOpts{
				SecLevel:     256,
				HashFamily:   "GMSM3",
				FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: keystorePath},
			},
		}
		cryptoLib.hashOpt, _ = bccsp.GetHashOpt("GMSM3")
	}

	cryptoLib.csp, err = f.Get(opts)
	if err != nil {
		return nil, err
	}
	cryptoLib.keyImportOpt = &bccsp.ECDSAPrivateKeyImportOpts{Format: bccsp.ECDSAPrivateKeyFormat_Hex}
	cryptoLib.tempPubkeyImportOpt = &bccsp.ECDSAS256PublicKeyImportOpts{Temporary: true}
	cryptoLib.keyGenOpt = &bccsp.ECDSAS256KeyGenOpts{Temporary: false}
	cryptoLib.tempkeyGenOpt = &bccsp.ECDSAS256KeyGenOpts{Temporary: true}
	if cryptoType == CryptoType_GM2_256 {
		cryptoLib.keyImportOpt = &bccsp.GMSM2PrivateKeyImportOpts{}
		cryptoLib.tempPubkeyImportOpt = &bccsp.GMSM2PublicKeyImportOpts{Temporary: true}
		cryptoLib.keyGenOpt = &bccsp.GMSM2KeyGenOpts{}
		cryptoLib.tempkeyGenOpt = &bccsp.GMSM2KeyGenOpts{Temporary: true}
	}
	myCryptoLib = cryptoLib
	return cryptoLib, nil
}
func (lib *CryptoLib) Hash(data ...[]byte) []byte {

	hf, _ := lib.csp.GetHash(lib.hashOpt)
	for _, b := range data {
		hf.Write(b)
	}
	hash := hf.Sum(nil)
	return hash
}
func Hash(data ...[]byte) []byte {
	if myCryptoLib == nil {
		_, err := InitDefaultCryptoLib()
		if err != nil {
			return nil
		}
	}
	return myCryptoLib.Hash(data...)
}
func HashResult(data ...[]byte) common.Hash {
	b := Hash(data...)
	return common.BytesToHash(b)
}
func (lib *CryptoLib) GetHash() (hash.Hash, error) {
	return lib.csp.GetHash(lib.hashOpt)
}
func GetHash() (hash.Hash, error) {
	if myCryptoLib == nil {
		_, err := InitDefaultCryptoLib()
		if err != nil {
			return nil, err
		}
	}
	return myCryptoLib.GetHash()
}
func (lib *CryptoLib) GenerateNewAddress(password []byte) (common.Address, error) {
	log.Debug("try to generate new private key to save in keystore, and return address.")
	opt, ok := lib.keyGenOpt.(*bccsp.ECDSAS256KeyGenOpts)
	if ok {
		opt.Password = password
		opt.Temporary = false
	} else {
		opt, ok := lib.keyGenOpt.(*bccsp.GMSM2KeyGenOpts)
		if ok {
			opt.Password = password
			opt.Temporary = false
		}
	}
	prvKey, err := lib.csp.KeyGen(lib.keyGenOpt)
	if err != nil {
		return common.Address{}, err
	}
	pubKey, _ := prvKey.PublicKey()
	pubKeyB, _ := pubKey.Bytes()
	addr := common.NewAddress(pubKey.SKI(), common.PublicKeyHash)
	lib.cacheAddrPriKey[addr] = prvKey

	log.Debugf("Generate new key ski:%x,pubkey:%x", pubKey.SKI(), pubKeyB)
	return addr, nil
}
func GenerateNewAddress(password []byte) (common.Address, error) {
	if myCryptoLib == nil {
		_, err := InitDefaultCryptoLib()
		if err != nil {
			return common.Address{}, err
		}
	}
	return myCryptoLib.GenerateNewAddress(password)
}
func GenerateNewKey() ([]byte, []byte, error) {
	if myCryptoLib == nil {
		_, err := InitDefaultCryptoLib()
		if err != nil {
			return nil, nil, err
		}
	}
	return myCryptoLib.GenerateNewKey()
}
func (lib *CryptoLib) GenerateNewKey() ([]byte, []byte, error) {
	prvKey, err := lib.csp.KeyGen(lib.tempkeyGenOpt)
	if err != nil {
		return nil, nil, err
	}
	prvKeyB, _ := prvKey.Bytes()
	pubKey, _ := prvKey.PublicKey()
	pubKeyB, _ := pubKey.Bytes()
	log.Debugf("Generate new key ski:%x", prvKey.SKI())
	return prvKeyB, pubKeyB, nil
}
func (lib *CryptoLib) SignByAddress(hash []byte, addr common.Address, password []byte) ([]byte, error) {
	if key, ok := lib.cacheAddrPriKey[addr]; ok {
		return lib.csp.Sign(key, hash, nil)
	}
	ski := addr.Bytes()
	log.Debugf("Try get key by ski:%x", ski)
	prvKey, err := lib.csp.GetKey(ski, &bccsp.ECDSAGetKeyOpts{Password: password})
	if err != nil {
		return nil, err
	}
	lib.cacheAddrPriKey[addr] = prvKey
	return lib.csp.Sign(prvKey, hash, nil)
}
func SignByAddress(hash []byte, addr common.Address, password []byte) ([]byte, error) {
	if myCryptoLib == nil {
		_, err := InitDefaultCryptoLib()
		if err != nil {
			return nil, err
		}
	}
	return myCryptoLib.SignByAddress(hash, addr, password)
}
func (lib *CryptoLib) GetPubKeyByAddress(addr common.Address, password []byte) ([]byte, error) {
	if pubkey, ok := lib.cacheAddrPubKey[addr]; ok {
		return pubkey.Bytes()
	}
	key, err := lib.csp.GetKey(addr.Bytes(), &bccsp.ECDSAGetKeyOpts{Password: password})
	if err != nil {
		return nil, err
	}
	var pubKey bccsp.Key
	if key.Private() {
		pubKey, _ = key.PublicKey()
	} else {
		pubKey = key
	}

	lib.cacheAddrPubKey[addr] = pubKey
	return pubKey.Bytes()
}
func GetPubKeyByAddress(addr common.Address, password []byte) ([]byte, error) {
	if myCryptoLib == nil {
		_, err := InitDefaultCryptoLib()
		if err != nil {
			return nil, err
		}
	}
	return myCryptoLib.GetPubKeyByAddress(addr, password)
}
func (lib *CryptoLib) VerifySign(pubkey, hash, signature []byte) bool {

	pubKey, err := lib.csp.KeyImport(pubkey, lib.tempPubkeyImportOpt)
	if err != nil {
		return false
	}
	valid, err := lib.csp.Verify(pubKey, signature, hash, nil)
	if err != nil {
		log.Errorf("Verify signature error:%s", err.Error())
		return false
	}
	return valid
}
func VerifySign(pubkey, hash, signature []byte) bool {
	if myCryptoLib == nil {
		_, err := InitDefaultCryptoLib()
		if err != nil {
			return false
		}
	}
	return myCryptoLib.VerifySign(pubkey, hash, signature)
}
func (lib *CryptoLib) GetKey(addr common.Address, password []byte) (bccsp.Key, error) {
	return lib.csp.GetKey(addr.Bytes(), &bccsp.ECDSAGetKeyOpts{Password: password})
}
func (lib *CryptoLib) StoreKey(privkey []byte, password []byte) error {
	log.Debug("Import private key to save in keystore.")
	opt, ok := lib.keyImportOpt.(*bccsp.ECDSAPrivateKeyImportOpts)
	if ok {
		opt.Password = password
		opt.Temporary = false
		opt.Format = bccsp.ECDSAPrivateKeyFormat_Hex
		lib.csp.KeyImport(privkey, opt)
	} else {
		opt, ok := lib.keyImportOpt.(*bccsp.GMSM2PrivateKeyImportOpts)
		if ok {
			opt.Password = password
			opt.Temporary = false
			lib.csp.KeyImport(privkey, opt)
		}
	}
	return nil

}
func GetInstance() *CryptoLib {
	if myCryptoLib == nil {
		_, err := InitDefaultCryptoLib()
		if err != nil {
			return nil
		}
	}
	return myCryptoLib
}
