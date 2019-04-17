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

	"github.com/palletone/go-palletone/common/log"
)

type HashType byte

const (
	HashType_SHA3_256 HashType = 0
	HashType_GM3      HashType = 1
)

type CryptoType byte

const (
	CryptoType_ECDSA_P256 CryptoType = 0
	CryptoType_GM2_256    CryptoType = 1
)

var csp bccsp.BCCSP
var hashOpt bccsp.HashOpts
var keyImportOpt bccsp.KeyImportOpts
var cacheAddrPriKey map[common.Address]bccsp.Key
var cacheAddrPubKey map[common.Address]bccsp.Key

func Init(hashType HashType, cryptoType CryptoType, keystorePath string) error {
	log.Debug("Try to initial bccsp instance.")
	cacheAddrPriKey = make(map[common.Address]bccsp.Key)
	cacheAddrPubKey = make(map[common.Address]bccsp.Key)
	f := &factory.SWFactory{}
	opts := &factory.FactoryOpts{
		SwOpts: &factory.SwOpts{
			SecLevel:     256,
			HashFamily:   "SHA3",
			FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: keystorePath},
		},
	}
	var err error
	hashOpt, err = bccsp.GetHashOpt("SHA3_256")
	if err != nil {
		return err
	}
	if hashType == HashType_GM3 {
		opts = &factory.FactoryOpts{
			SwOpts: &factory.SwOpts{
				SecLevel:     256,
				HashFamily:   "GMSM3",
				FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: keystorePath},
			},
		}
		hashOpt, _ = bccsp.GetHashOpt("GMSM3")
	}

	csp, err = f.Get(opts)
	if err != nil {
		return err
	}
	keyImportOpt = &bccsp.ECDSAS256PublicKeyImportOpts{}
	if cryptoType == CryptoType_GM2_256 {
		keyImportOpt = &bccsp.GMSM2PublicKeyImportOpts{}
	}
	return nil
}
func Hash(data []byte) common.Hash {

	hf, _ := csp.GetHash(hashOpt)
	hf.Write(data)
	hash := hf.Sum(nil)
	return common.BytesToHash(hash)
}
func GenerateNewAddress() (common.Address, error) {
	prvKey, err := csp.KeyGen(&bccsp.ECDSAS256KeyGenOpts{Temporary: false})
	if err != nil {
		return common.Address{}, err
	}
	addr := common.NewAddress(prvKey.SKI(), common.PublicKeyHash)
	cacheAddrPriKey[addr] = prvKey
	log.Debugf("Generate new key ski:%x", prvKey.SKI())
	return addr, nil
}

func SignByAddress(hash []byte, addr common.Address) ([]byte, error) {
	if key, ok := cacheAddrPriKey[addr]; ok {
		return csp.Sign(key, hash, nil)
	}
	ski := addr.Bytes()
	log.Debugf("Try get key by ski:%x", ski)
	prvKey, err := csp.GetKey(ski)
	if err != nil {
		return nil, err
	}
	cacheAddrPriKey[addr] = prvKey
	return csp.Sign(prvKey, hash, nil)
}
func GetPubKeyByAddress(addr common.Address) ([]byte, error) {
	if pubkey, ok := cacheAddrPubKey[addr]; ok {
		return pubkey.Bytes()
	}
	key, err := csp.GetKey(addr.Bytes())
	if err != nil {
		return nil, err
	}
	var pubKey bccsp.Key
	if key.Private() {
		pubKey, _ = key.PublicKey()
	} else {
		pubKey = key
	}

	cacheAddrPubKey[addr] = pubKey
	return pubKey.Bytes()
}
func VerifySign(pubkey, hash, signature []byte) bool {
	pubKey, err := csp.KeyImport(pubkey, &bccsp.ECDSAS256PublicKeyImportOpts{Temporary: true})
	if err != nil {
		return false
	}
	valid, err := csp.Verify(pubKey, signature, hash, nil)
	if err != nil {
		log.Errorf("Verify signature error:%s", err.Error())
		return false
	}
	return valid
}
