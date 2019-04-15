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
func Init(hashType HashType, cryptoType CryptoType, keystorePath string) error {
	f := &factory.SWFactory{}

	opts := &factory.FactoryOpts{
		SwOpts: &factory.SwOpts{
			SecLevel:     256,
			HashFamily:   "SHA3",
			FileKeystore: &factory.FileKeystoreOpts{KeyStorePath: keystorePath},
		},
	}
	hashOpt, _ = bccsp.GetHashOpt("SHA3")
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
	var err error
	csp, err = f.Get(opts)
	if err != nil {
		return err
	}
	keyImportOpt=&bccsp.ECDSAS256PublicKeyImportOpts{}
	if cryptoType== CryptoType_GM2_256{
	keyImportOpt=&bccsp.GMSM2PublicKeyImportOpts{}
	}
	return nil
}
func Hash(data []byte) common.Hash {

	hf, _ := csp.GetHash(hashOpt)
	hf.Write(data)
	hash := hf.Sum(nil)
	return common.BytesToHash( hash)
}
func SignByAddress(hash []byte, addr common.Address ) ([]byte, error) {
	ski:=addr.Bytes()
	prvKey,err:=csp.GetKey(ski)
	if err!=nil{
		return nil,err
	}
	return csp.Sign(prvKey,hash,nil)
}
func VerifySign(pubkey, hash, signature []byte) bool {
	pubKey,err:=csp.KeyImport(pubkey,&bccsp.ECDSAS256PublicKeyImportOpts{})
	if err!=nil{
		return false
	}
	valid, err := csp.Verify(pubKey, signature, hash, nil)
	if err!=nil {
		log.Errorf("Verify signature error:%s", err.Error())
		return false
	}
	return valid
}